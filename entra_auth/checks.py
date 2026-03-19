"""
entra_auth.checks
~~~~~~~~~~~~~~~~~
Django system checks that validate the ENTRA_AUTH configuration at startup.
Run explicitly with:  python manage.py check
"""

from django.core.checks import Error, Tags, Warning, register


@register(Tags.security)
def check_entra_settings(app_configs, **kwargs):
    from django.conf import settings

    errors = []
    raw: dict = getattr(settings, "ENTRA_AUTH", None)

    if raw is None:
        errors.append(
            Error(
                "settings.ENTRA_AUTH is not defined.",
                hint="Add an ENTRA_AUTH dict to your settings file.",
                id="entra_auth.E001",
            )
        )
        return errors

    # --- Required settings ---
    for key in ("CLIENT_ID", "TENANT_ID"):
        if not raw.get(key):
            errors.append(
                Error(
                    f"settings.ENTRA_AUTH['{key}'] is required but not set.",
                    id=f"entra_auth.E00{2 if key == 'CLIENT_ID' else 3}",
                )
            )

    # --- Client secret ---
    if not raw.get("CLIENT_SECRET"):
        errors.append(
            Warning(
                "settings.ENTRA_AUTH['CLIENT_SECRET'] is not set. "
                "This is only valid for public-client applications.",
                hint="Add CLIENT_SECRET for web-app (confidential client) flows.",
                id="entra_auth.W001",
            )
        )

    # --- Authentication backend ---
    backends = getattr(settings, "AUTHENTICATION_BACKENDS", [])
    if "entra_auth.backends.EntraAuthBackend" not in backends:
        errors.append(
            Error(
                "'entra_auth.backends.EntraAuthBackend' is not in "
                "settings.AUTHENTICATION_BACKENDS.",
                hint="Add 'entra_auth.backends.EntraAuthBackend' to AUTHENTICATION_BACKENDS.",
                id="entra_auth.E004",
            )
        )

    # --- Session app ---
    installed = getattr(settings, "INSTALLED_APPS", [])
    if "django.contrib.sessions" not in installed:
        errors.append(
            Error(
                "'django.contrib.sessions' must be in INSTALLED_APPS.",
                id="entra_auth.E005",
            )
        )

    # --- Session middleware ---
    middleware = getattr(settings, "MIDDLEWARE", [])
    if "django.contrib.sessions.middleware.SessionMiddleware" not in middleware:
        errors.append(
            Error(
                "SessionMiddleware must be in MIDDLEWARE.",
                id="entra_auth.E006",
            )
        )

    # --- Session engine: warn if using signed cookies ---
    # Cookie-based sessions cannot store the MSAL flow state (too large) and
    # are not safe for token cache storage.
    session_engine = getattr(settings, "SESSION_ENGINE", "django.contrib.sessions.backends.db")
    if "signed_cookies" in session_engine:
        errors.append(
            Error(
                "SESSION_ENGINE is set to signed_cookies. "
                "entra_auth stores MSAL token state in the session which "
                "exceeds cookie size limits and must not be stored client-side.",
                hint="Use a server-side session backend: db, cache, or cached_db.",
                id="entra_auth.E007",
            )
        )

    # --- HTTPS in production ---
    # Warn if REDIRECT_URI is configured with http:// in a non-debug environment
    redirect_uri = raw.get("REDIRECT_URI", "")
    debug = getattr(settings, "DEBUG", False)
    if redirect_uri and redirect_uri.startswith("http://") and not debug:
        errors.append(
            Warning(
                "settings.ENTRA_AUTH['REDIRECT_URI'] uses http:// in a "
                "non-DEBUG environment. Microsoft Entra ID requires HTTPS "
                "for redirect URIs in production.",
                hint="Update REDIRECT_URI to use https://",
                id="entra_auth.W002",
            )
        )

    # --- POST_LOGIN_REDIRECT hook: validate dotted path if set ---
    hook_path = raw.get("POST_LOGIN_REDIRECT")
    if hook_path:
        if not isinstance(hook_path, str) or "." not in hook_path:
            errors.append(
                Error(
                    "settings.ENTRA_AUTH['POST_LOGIN_REDIRECT'] must be a "
                    "dotted Python path string, e.g. 'myapp.views.auth.post_login_redirect'.",
                    id="entra_auth.E008",
                )
            )

    return errors