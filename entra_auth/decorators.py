"""
entra_auth.decorators
~~~~~~~~~~~~~~~~~~~~~
View decorators for fine-grained access control.

    from entra_auth.decorators import entra_login_required, entra_group_required

    @entra_login_required
    def my_view(request):
        ...

    @entra_group_required("django-admins")
    def admin_only_view(request):
        ...

    @entra_login_not_required
    def public_view(request):
        # Exempt from EntraLoginRequiredMiddleware
        ...
"""

import functools

from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme

from .conf import entra_settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_redirect_to_login(request, redirect_field_name="next"):
    """
    Redirect to the Entra login page, appending ?next= only if the current
    URL passes the same-host safety check to prevent open-redirect attacks.
    """
    login_url = entra_settings.LOGIN_URL
    next_url = request.get_full_path()
    if url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts=request.get_host(),
        require_https=request.is_secure(),
    ):
        return redirect(f"{login_url}?{redirect_field_name}={next_url}")
    return redirect(login_url)


# ---------------------------------------------------------------------------
# entra_login_required
# ---------------------------------------------------------------------------

def entra_login_required(view_func=None, *, redirect_field_name="next"):
    """
    Decorator that requires the user to be authenticated via Entra ID.
    Redirects to the Entra login page on failure.

    The ``next`` parameter is validated against the current host to prevent
    open-redirect attacks.

    Usage:
        @entra_login_required
        def my_view(request): ...

        # Class-based views
        @method_decorator(entra_login_required, name="dispatch")
        class MyView(View): ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated:
                return func(request, *args, **kwargs)
            return _safe_redirect_to_login(request, redirect_field_name)
        return wrapper

    if view_func is not None:
        # Used as @entra_login_required (no parentheses)
        return decorator(view_func)
    # Used as @entra_login_required(...) with arguments
    return decorator


# ---------------------------------------------------------------------------
# entra_group_required
# ---------------------------------------------------------------------------

def entra_group_required(*group_names: str, raise_exception: bool = False):
    """
    Decorator that requires the user to belong to at least one of the named
    Django groups.

    If raise_exception is True, raises PermissionDenied (→ 403) instead of
    redirecting to login.

        @entra_group_required("finance", "admins")
        def sensitive_view(request):
            ...
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                if raise_exception:
                    raise PermissionDenied
                return _safe_redirect_to_login(request)
            user_groups = set(
                request.user.groups.values_list("name", flat=True)
            )
            if user_groups.intersection(group_names):
                return view_func(request, *args, **kwargs)
            if raise_exception:
                raise PermissionDenied
            return redirect(entra_settings.LOGIN_URL)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# entra_login_not_required  (middleware opt-out)
# ---------------------------------------------------------------------------

def entra_login_not_required(view_func):
    """
    Mark a view as publicly accessible, exempting it from
    ``EntraLoginRequiredMiddleware``.

        @entra_login_not_required
        def health_check(request):
            return HttpResponse("ok")
    """
    view_func._entra_login_not_required = True

    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        request._entra_login_not_required = True
        return view_func(request, *args, **kwargs)
    return wrapper