"""
entra_auth.views
~~~~~~~~~~~~~~~~
Three views cover the entire OAuth2 / OIDC flow:

  /entra/login/     → redirect user to Microsoft login
  /entra/callback/  → handle the redirect back from Microsoft
  /entra/logout/    → sign the user out of Django (+ optionally Entra)
"""

import logging

from django.contrib import auth, messages
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View

from .conf import entra_settings
from .msal_client import (
    _clear_cache,
    acquire_token_by_auth_code_flow,
    initiate_auth_code_flow,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_redirect_uri(request: HttpRequest) -> str:
    """Return the absolute callback URL to register with MSAL."""
    if entra_settings.REDIRECT_URI:
        return str(entra_settings.REDIRECT_URI)
    return str(request.build_absolute_uri("/entra/callback/"))


def _safe_next_url(request: HttpRequest, fallback: str) -> str:
    """
    Return the ``next`` URL from POST/GET/session only if it is safe to
    redirect to (same host, allowed scheme).  Falls back to *fallback* if
    the value is missing or fails the safety check.

    This prevents open-redirect attacks where an attacker crafts a login
    link whose ``next`` parameter points to an external phishing site.
    """
    next_url = (
        request.POST.get("next")
        or request.GET.get("next")
        or request.session.get("_entra_next")
        or ""
    )
    if next_url and url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts=request.get_host(),
        require_https=request.is_secure(),
    ):
        return next_url
    return fallback


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

class EntraLoginView(View):
    """
    Kick off the OAuth2 Authorization Code + PKCE flow.

    Accepts an optional ``next`` GET parameter (stored in session) so the user
    lands on the page they originally requested after authentication.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated:
            return redirect(_safe_next_url(request, settings.LOGIN_REDIRECT_URL))

        # Persist the post-login redirect target only if it is safe
        next_url = request.GET.get("next", "")
        if next_url and url_has_allowed_host_and_scheme(
            url=next_url,
            allowed_hosts=request.get_host(),
            require_https=request.is_secure(),
        ):
            request.session["_entra_next"] = next_url

        redirect_uri = _build_redirect_uri(request)
        try:
            flow = initiate_auth_code_flow(request, redirect_uri=redirect_uri)
        except Exception:
            log.exception("Failed to initiate auth-code flow")
            return HttpResponse("Authentication configuration error.", status=500)

        return HttpResponseRedirect(flow["auth_uri"])


class EntraCallbackView(View):
    """
    Receive the auth code from Microsoft, exchange it for tokens, then log the
    user into Django.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        # Microsoft sends errors as query params
        if "error" in request.GET:
            error = request.GET.get("error")
            description = request.GET.get("error_description", "")
            log.warning("Entra auth error: %s — %s", error, description)
            messages.error(
                request,
                f"Sign-in failed: {description or error}",
            )
            return redirect(entra_settings.LOGIN_URL)

        try:
            msal_result = acquire_token_by_auth_code_flow(
                request,
                auth_response=request.GET.dict(),
            )
        except Exception:
            log.exception("Failed to acquire token from auth code")
            messages.error(request, "Authentication failed. Please try again.")
            return redirect(entra_settings.LOGIN_URL)

        if "error" in msal_result:
            log.warning(
                "Token acquisition error: %s — %s",
                msal_result.get("error"),
                msal_result.get("error_description", ""),
            )
            messages.error(
                request,
                msal_result.get("error_description", "Sign-in failed."),
            )
            return redirect(entra_settings.LOGIN_URL)

        user = auth.authenticate(request, msal_result=msal_result)
        if user is None:
            messages.error(request, "Your account is not authorised to access this site.")
            return redirect(entra_settings.LOGIN_URL)

        auth.login(request, user, backend="entra_auth.backends.EntraAuthBackend")
        log.info("User %s authenticated via Entra ID", user.username)

        request.session.save()

        # Call post-login hook if configured
        hook_response = _call_post_login_hook(request, user)
        if hook_response is not None:
            return hook_response

        next_url = _safe_next_url(request, settings.LOGIN_REDIRECT_URL)
        # Clear the stored next URL now that we've consumed it
        request.session.pop("_entra_next", None)
        return redirect(next_url)


class EntraLogoutView(View):
    """
    Log the user out of Django and redirect to Microsoft's global sign-out
    endpoint so the Entra session is also terminated.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        return self._logout(request)

    def post(self, request: HttpRequest) -> HttpResponse:
        return self._logout(request)

    def _logout(self, request: HttpRequest) -> HttpResponse:
        _clear_cache(request)
        auth.logout(request)

        post_logout_uri = request.build_absolute_uri(
            entra_settings.LOGOUT_REDIRECT_URL
        )
        entra_logout_url = (
            f"{entra_settings.AUTHORITY_URL}/oauth2/v2.0/logout"
            f"?post_logout_redirect_uri={post_logout_uri}"
        )
        return HttpResponseRedirect(entra_logout_url)


# ---------------------------------------------------------------------------
# Post-login hook
# ---------------------------------------------------------------------------

def _call_post_login_hook(request, user):
    """
    Call the POST_LOGIN_REDIRECT hook function if configured in ENTRA_AUTH.

    The hook signature is:
        fn(request, user) -> HttpResponse | None

    Return an HttpResponse to override the default redirect entirely,
    or return None to proceed with the normal LOGIN_REDIRECT_URL redirect.

    Example in settings.py:
        ENTRA_AUTH = {
            ...
            "POST_LOGIN_REDIRECT": "myapp.views.auth.post_login_redirect",
        }
    """
    hook_path = entra_settings.POST_LOGIN_REDIRECT
    if not hook_path:
        return None

    try:
        module_path, func_name = hook_path.rsplit(".", 1)
        import importlib
        module = importlib.import_module(module_path)
        hook_fn = getattr(module, func_name)
        return hook_fn(request, user)
    except Exception:
        log.exception("Error calling POST_LOGIN_REDIRECT hook: %s", hook_path)
        return None


# ---------------------------------------------------------------------------
# Deferred import (settings may not be ready at module load time)
# ---------------------------------------------------------------------------

from django.conf import settings  # noqa: E402