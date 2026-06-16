"""
entra_auth.token_refresh_middleware
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Middleware that automatically refreshes access tokens before they expire,
ensuring users maintain their sessions for as long as the refresh token
is valid (typically 90 days) without being forced to re-authenticate every
hour when the access token expires.

This implements the proper OAuth 2.0 refresh flow for long-lived sessions.

Usage -- add **after** SessionMiddleware and AuthenticationMiddleware,
but **before** EntraLoginRequiredMiddleware:

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        ...
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "entra_auth.token_refresh_middleware.EntraTokenRefreshMiddleware",  # <- add here
        "entra_auth.middleware.EntraLoginRequiredMiddleware",
    ]

This middleware:
1. Checks if the user is authenticated via Entra
2. Checks if their access token is about to expire (within 5 minutes)
3. Automatically refreshes it using the refresh token
4. Only forces re-authentication if the refresh token has also expired
"""

import logging
from django.contrib import auth
from django.shortcuts import redirect

from .conf import entra_settings
from .msal_client import refresh_token_if_needed

log = logging.getLogger(__name__)


class EntraTokenRefreshMiddleware:
    """
    Automatically refresh access tokens before they expire to maintain
    long-lived sessions without forcing users to re-authenticate every hour.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only process authenticated users
        if request.user.is_authenticated:
            # Skip token refresh for the auth flow URLs themselves
            if self._is_auth_flow_url(request):
                return self.get_response(request)
            
            # Attempt to refresh the token if it's about to expire
            if not refresh_token_if_needed(request):
                # Refresh failed -- refresh token has likely expired (after ~90 days)
                # Log the user out and redirect to login
                log.info(
                    "User %s refresh token expired, logging out and redirecting to login",
                    request.user.username,
                )
                auth.logout(request)
                
                # Preserve the current URL so user can return after re-authenticating
                next_url = request.get_full_path()
                login_url = entra_settings.LOGIN_URL
                return redirect(f"{login_url}?next={next_url}")
        
        return self.get_response(request)

    def _is_auth_flow_url(self, request) -> bool:
        """Check if this is an auth flow URL that should skip token refresh."""
        path = request.path_info
        return path.startswith("/entra/login/") or \
               path.startswith("/entra/callback/") or \
               path.startswith("/entra/logout/")
