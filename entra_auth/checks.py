"""
entra_auth.checks
~~~~~~~~~~~~~~~~~
Django system checks that validate the ENTRA_AUTH configuration at startup.
Run explicitly with:  python manage.py check
"""

from django.core.checks import Error, Warning, register


@register.check(deploy=False)
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

    for key in ("CLIENT_ID", "TENANT_ID"):
        if not raw.get(key):
            errors.append(
                Error(
                    f"settings.ENTRA_AUTH['{key}'] is required but not set.",
                    id=f"entra_auth.E00{2 if key == 'CLIENT_ID' else 3}",
                )
            )

    if not raw.get("CLIENT_SECRET"):
        errors.append(
            Warning(
                "settings.ENTRA_AUTH['CLIENT_SECRET'] is not set. "
                "This is only valid for public-client applications.",
                hint="Add CLIENT_SECRET for web-app (confidential client) flows.",
                id="entra_auth.W001",
            )
        )

    # Check backend is registered
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

    # Check session engine is enabled
    installed = getattr(settings, "INSTALLED_APPS", [])
    if "django.contrib.sessions" not in installed:
        errors.append(
            Error(
                "'django.contrib.sessions' must be in INSTALLED_APPS.",
                id="entra_auth.E005",
            )
        )

    middleware = getattr(settings, "MIDDLEWARE", [])
    if "django.contrib.sessions.middleware.SessionMiddleware" not in middleware:
        errors.append(
            Error(
                "SessionMiddleware must be in MIDDLEWARE.",
                id="entra_auth.E006",
            )
        )

    return errors
