"""
entra_auth.conf
~~~~~~~~~~~~~~~
Settings are read from a single dict in your Django settings:

    ENTRA_AUTH = {
        # --- Required ---
        "CLIENT_ID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "CLIENT_SECRET": "your-client-secret",          # omit for public clients
        "TENANT_ID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        # or use "common" / "organizations" / "consumers" for multi-tenant

        # --- Optional ---
        "REDIRECT_URI": "https://yourapp.example.com/entra/callback/",
        # Defaults to building from request if omitted.

        "SCOPES": ["User.Read"],
        # Add more MS Graph scopes as needed, e.g. "Mail.Read", "Calendars.Read"

        "LOGIN_URL": "/entra/login/",
        # Where unauthenticated users are redirected (used by middleware)

        "AUTHORITY": None,
        # Override the full authority URL. If None, built from TENANT_ID.

        "LOGOUT_REDIRECT_URL": "/",
        # Where to send the user after logout

        "GRAPH_USER_FIELDS": ["id", "displayName", "mail", "userPrincipalName",
                              "givenName", "surname", "jobTitle", "officeLocation"],
        # Graph /me fields to fetch and store on the Django user

        "CREATE_USERS": True,
        # Auto-create Django users on first login

        "UPDATE_USER_ON_LOGIN": True,
        # Re-sync user fields from Graph on every login

        "USERNAME_FIELD": "email",
        # "email" (uses mail/userPrincipalName) or "oid" (uses Entra object ID)

        "GROUPS_CLAIM": "groups",
        # Token claim to read group memberships from (requires optional claims config)

        "GROUPS_MAP": {},
        # Map Entra group object-IDs/names → Django group names
        # e.g. {"aad-group-oid": "django-group-name"}

        "TOKEN_CACHE_TIMEOUT": 3600,
        # Seconds to keep the serialised MSAL token cache in the Django session

        "EXEMPT_URLS": [],
        # Extra URL patterns exempt from the require-login middleware
        # (login/callback/logout URLs are always exempt automatically)
    }
"""

from django.conf import settings

_DEFAULTS = {
    "CLIENT_SECRET": None,
    "REDIRECT_URI": None,
    "SCOPES": ["User.Read"],
    "LOGIN_URL": "/entra/login/",
    "AUTHORITY": None,
    "LOGOUT_REDIRECT_URL": "/",
    "GRAPH_USER_FIELDS": [
        "id",
        "displayName",
        "mail",
        "userPrincipalName",
        "givenName",
        "surname",
        "jobTitle",
        "officeLocation",
    ],
    "CREATE_USERS": True,
    "UPDATE_USER_ON_LOGIN": True,
    "USERNAME_FIELD": "email",
    "GROUPS_CLAIM": "groups",
    "GROUPS_MAP": {},
    "TOKEN_CACHE_TIMEOUT": 3600,
    "EXEMPT_URLS": [],
    "POST_LOGIN_REDIRECT": None,
}

_REQUIRED = {"CLIENT_ID", "TENANT_ID"}


class EntraAuthSettings:
    """Lazy proxy around settings.ENTRA_AUTH."""

    def __getattr__(self, name):
        raw = getattr(settings, "ENTRA_AUTH", {})
        if name in _REQUIRED and name not in raw:
            raise ImproperlyConfigured(
                f"settings.ENTRA_AUTH['{name}'] is required but not set."
            )
        if name in raw:
            return raw[name]
        if name in _DEFAULTS:
            return _DEFAULTS[name]
        raise AttributeError(f"Unknown ENTRA_AUTH setting: {name!r}")

    @property
    def AUTHORITY_URL(self):
        if self.AUTHORITY:
            return self.AUTHORITY
        return f"https://login.microsoftonline.com/{self.TENANT_ID}"


from django.core.exceptions import ImproperlyConfigured  # noqa: E402

entra_settings = EntraAuthSettings()
