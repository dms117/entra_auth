"""
entra_auth.graph
~~~~~~~~~~~~~~~~
Thin helper for Microsoft Graph API calls.

We deliberately use the *requests* library (a near-universal Django
dependency) rather than pulling in the entire msgraph-sdk package, which
drags in a large dependency tree.  The Graph REST API is stable and
well-documented, so raw HTTP calls are transparent, easy to audit, and
won't break when SDK internals change.

If you need advanced Graph features (batch, streaming, etc.) you can swap
this module for msgraph-sdk without touching the rest of the app.
"""

import logging

import requests

log = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ---------------------------------------------------------------------------
# Low-level helper
# ---------------------------------------------------------------------------

def graph_get(access_token: str, path: str, **params) -> dict:
    """
    Perform an authenticated GET against the Graph v1.0 endpoint.

    :param access_token: A valid Bearer token.
    :param path: URL path relative to /v1.0, e.g. ``/me``.
    :param params: Query-string parameters passed to requests.
    :raises GraphError: on non-2xx responses.
    """
    url = f"{_GRAPH_BASE}{path}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=10,
    )
    if not resp.ok:
        raise GraphError(
            f"Graph {resp.status_code} for {path}: {resp.text[:200]}"
        )
    return resp.json()


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def get_me(access_token: str, fields: list[str] | None = None) -> dict:
    """
    Fetch the signed-in user's profile from Graph /me.

    :param fields: list of ``$select`` fields. Defaults to all.
    """
    params = {}
    if fields:
        params["$select"] = ",".join(fields)
    return graph_get(access_token, "/me", **params)


def get_me_groups(access_token: str) -> list[dict]:
    """
    Fetch all groups the signed-in user is a member of.
    Handles paging automatically.
    """
    groups = []
    data = graph_get(access_token, "/me/memberOf")
    groups.extend(data.get("value", []))
    # Follow @odata.nextLink if present
    while next_link := data.get("@odata.nextLink"):
        resp = requests.get(
            next_link,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        groups.extend(data.get("value", []))
    return groups


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GraphError(Exception):
    """Raised when a Graph API call returns a non-2xx response."""
