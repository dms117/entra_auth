"""
entra_auth.msal_client
~~~~~~~~~~~~~~~~~~~~~~
Thin wrappers around msal.ConfidentialClientApplication /
msal.PublicClientApplication that persist the MSAL token cache inside the
Django session so tokens survive between requests without an external cache.
"""
import logging
import time
import msal

from .conf import entra_settings


# ---------------------------------------------------------------------------
# Token-cache helpers
# ---------------------------------------------------------------------------

_CACHE_SESSION_KEY = "_entra_token_cache"
_TOKEN_EXPIRY_KEY = "_entra_token_expiry"
_REFRESH_TOKEN_KEY = "_entra_refresh_token"

log = logging.getLogger(__name__)


def _load_cache(request) -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if _CACHE_SESSION_KEY in request.session:
        cache.deserialize(request.session[_CACHE_SESSION_KEY])
    return cache


def _save_cache(request, cache: msal.SerializableTokenCache) -> None:
    if cache.has_state_changed:
        request.session[_CACHE_SESSION_KEY] = cache.serialize()
        # Keep the session alive as long as the cache is valid
        request.session.set_expiry(entra_settings.TOKEN_CACHE_TIMEOUT)


def _clear_cache(request) -> None:
    request.session.pop(_CACHE_SESSION_KEY, None)
    request.session.pop(_TOKEN_EXPIRY_KEY, None)
    request.session.pop(_REFRESH_TOKEN_KEY, None)


def _store_token_metadata(request, msal_result: dict) -> None:
    """
    Store token expiry time and refresh token in session for proactive refresh.
    
    The MSAL token cache handles refresh automatically during acquire_token_silent,
    but we track expiry explicitly so middleware can trigger refresh before the
    access token expires.
    """
    if "expires_in" in msal_result:
        # expires_in is in seconds; store the absolute expiry timestamp
        expiry_time = time.time() + msal_result["expires_in"]
        request.session[_TOKEN_EXPIRY_KEY] = expiry_time
        log.debug("Stored token expiry: %s seconds from now", msal_result["expires_in"])
    
    if "refresh_token" in msal_result:
        # Store refresh token explicitly (MSAL cache also stores it, but this
        # makes it easier for middleware to check if refresh is possible)
        request.session[_REFRESH_TOKEN_KEY] = msal_result["refresh_token"]
        log.debug("Stored refresh token in session")


def get_token_expiry(request) -> float | None:
    """
    Return the access token expiry timestamp (seconds since epoch), or None
    if not known.
    """
    return request.session.get(_TOKEN_EXPIRY_KEY)


def is_token_expired(request, buffer_seconds: int = 300) -> bool:
    """
    Check if the access token is expired or will expire within buffer_seconds.
    
    Default buffer is 5 minutes to ensure we refresh proactively before the
    token becomes invalid mid-request.
    """
    expiry = get_token_expiry(request)
    if expiry is None:
        return False  # No expiry tracked, assume valid
    return time.time() >= (expiry - buffer_seconds)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def build_msal_app(
    request=None,
    *,
    cache: msal.SerializableTokenCache | None = None,
) -> msal.ClientApplication:
    """
    Return an MSAL client application.

    Pass *request* (a Django HttpRequest) to enable session-backed token
    caching.  Pass *cache* directly if you are managing the cache yourself.
    """
    if cache is None and request is not None:
        cache = _load_cache(request)

    kwargs = dict(
        client_id=entra_settings.CLIENT_ID,
        authority=entra_settings.AUTHORITY_URL,
        token_cache=cache,
    )

    if entra_settings.CLIENT_SECRET:
        return msal.ConfidentialClientApplication(
            client_credential=entra_settings.CLIENT_SECRET,
            **kwargs,
        )

    # Public client (e.g. desktop / mobile — uncommon for web apps but supported)
    return msal.PublicClientApplication(**kwargs)


# ---------------------------------------------------------------------------
# Auth-code flow helpers (used by views)
# ---------------------------------------------------------------------------

def initiate_auth_code_flow(request, *, redirect_uri: str) -> dict:
    app = build_msal_app(request)
    flow = app.initiate_auth_code_flow(
        scopes=[str(s) for s in entra_settings.SCOPES],
        redirect_uri=str(redirect_uri),
    )
    request.session["_entra_auth_flow"] = flow
    request.session.save()  # force save immediately
    #log.warning("DEBUG initiate: session key=%s flow keys=%s", request.session.session_key, list(flow.keys()))
    return flow


def acquire_token_by_auth_code_flow(request, *, auth_response: dict) -> dict:
    flow = request.session.get("_entra_auth_flow", {})
    #log.warning("DEBUG callback: session key=%s flow found=%s", request.session.session_key, bool(flow))
    app = build_msal_app(request)
    result = app.acquire_token_by_auth_code_flow(
        auth_code_flow=flow,
        auth_response=auth_response,
    )
    _save_cache(request, app.token_cache)
    
    # Store token metadata for proactive refresh
    if "access_token" in result:
        _store_token_metadata(request, result)
    
    return result


def acquire_token_silent(request) -> dict | None:
    """
    Try to obtain a valid access token silently from the cache (may refresh
    automatically using the refresh token if the access token is expired).
    
    Returns None if no cached account is found or if the refresh token has
    also expired (user needs to re-authenticate).

    Useful for views that need to call Graph without forcing a re-login.
    """
    app = build_msal_app(request)
    accounts = app.get_accounts()
    if not accounts:
        log.debug("acquire_token_silent: no accounts in cache")
        return None

    result = app.acquire_token_silent(
        scopes=entra_settings.SCOPES,
        account=accounts[0],
    )
    _save_cache(request, app.token_cache)
    
    # Update token metadata if we got a new token
    if result and "access_token" in result:
        _store_token_metadata(request, result)
        log.debug("Token refreshed successfully via acquire_token_silent")
    elif result and "error" in result:
        log.warning(
            "acquire_token_silent failed: %s — %s",
            result.get("error"),
            result.get("error_description", ""),
        )
    
    return result


def refresh_token_if_needed(request) -> bool:
    """
    Proactively refresh the access token if it's about to expire.
    
    Returns True if the token is valid (either already valid or successfully
    refreshed), False if refresh failed and user needs to re-authenticate.
    
    This is called by middleware before each request to ensure the token
    remains valid throughout the request lifecycle.
    """
    if not is_token_expired(request):
        # Token is still valid, no action needed
        return True
    
    log.info("Access token expired or expiring soon, attempting silent refresh")
    result = acquire_token_silent(request)
    
    if result and "access_token" in result:
        log.info("Access token refreshed successfully")
        return True
    
    # Refresh failed — user needs to re-authenticate
    log.warning("Token refresh failed, user will need to re-authenticate")
    return False
