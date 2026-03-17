"""
entra_auth.msal_client
~~~~~~~~~~~~~~~~~~~~~~
Thin wrappers around msal.ConfidentialClientApplication /
msal.PublicClientApplication that persist the MSAL token cache inside the
Django session so tokens survive between requests without an external cache.
"""

import msal

from .conf import entra_settings


# ---------------------------------------------------------------------------
# Token-cache helpers
# ---------------------------------------------------------------------------

_CACHE_SESSION_KEY = "_entra_token_cache"


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
    """
    Start an auth-code + PKCE flow.  Stores the flow state in the session and
    returns the dict returned by MSAL (contains ``auth_uri``).
    """
    app = build_msal_app(request)
    flow = app.initiate_auth_code_flow(
        scopes=entra_settings.SCOPES,
        redirect_uri=redirect_uri,
    )
    request.session["_entra_auth_flow"] = flow
    return flow


def acquire_token_by_auth_code_flow(request, *, auth_response: dict) -> dict:
    """
    Complete the auth-code flow.  Returns the MSAL result dict which contains
    ``access_token``, ``id_token_claims``, etc. on success, or ``error`` on
    failure.

    The token cache is automatically persisted back to the session.
    """
    app = build_msal_app(request)
    flow = request.session.pop("_entra_auth_flow", {})
    result = app.acquire_token_by_auth_code_flow(
        auth_code_flow=flow,
        auth_response=auth_response,
    )
    # Persist updated cache (new tokens, refreshed tokens, etc.)
    _save_cache(request, app.token_cache)
    return result


def acquire_token_silent(request) -> dict | None:
    """
    Try to obtain a valid access token silently from the cache (may refresh
    automatically).  Returns None if no cached account is found.

    Useful for views that need to call Graph without forcing a re-login.
    """
    app = build_msal_app(request)
    accounts = app.get_accounts()
    if not accounts:
        return None

    result = app.acquire_token_silent(
        scopes=entra_settings.SCOPES,
        account=accounts[0],
    )
    _save_cache(request, app.token_cache)
    return result
