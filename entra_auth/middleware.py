"""
entra_auth.middleware
~~~~~~~~~~~~~~~~~~~~~
Optional middleware that enforces authentication on every URL unless the URL
is explicitly exempted.

Usage — add **after** SessionMiddleware and AuthenticationMiddleware:

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        ...
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "entra_auth.middleware.EntraLoginRequiredMiddleware",  # ← add here
    ]

Exempted URLs:
  - /entra/login/  (always)
  - /entra/callback/  (always)
  - /entra/logout/  (always)
  - settings.ENTRA_AUTH["EXEMPT_URLS"]  (regex patterns)
  - Any URL decorated with @entra_auth.decorators.entra_login_not_required
"""

import re

from django.conf import settings
from django.shortcuts import redirect

from .conf import entra_settings

# URLs that are always exempt (the auth flow itself)
_ALWAYS_EXEMPT = [
    r"^/entra/login/",
    r"^/entra/callback/",
    r"^/entra/logout/",
]

# Django admin login is often kept as a fallback — exempt it too
_ADMIN_EXEMPT = [r"^/admin/login/", r"^/admin/logout/"]


class EntraLoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        user_exempt = entra_settings.EXEMPT_URLS
        patterns = _ALWAYS_EXEMPT + _ADMIN_EXEMPT + list(user_exempt)
        self._exempt_re = [re.compile(p) for p in patterns]

    def __call__(self, request):
        if not self._is_exempt(request) and not request.user.is_authenticated:
            login_url = entra_settings.LOGIN_URL
            return redirect(f"{login_url}?next={request.get_full_path()}")
        return self.get_response(request)

    def _is_exempt(self, request) -> bool:
        # Per-view opt-out via decorator
        if getattr(request, "_entra_login_not_required", False):
            return True
        path = request.path_info
        return any(pattern.match(path) for pattern in self._exempt_re)
