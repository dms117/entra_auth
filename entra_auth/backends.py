"""
entra_auth.backends
~~~~~~~~~~~~~~~~~~~
Custom Django authentication backend.

Add to settings.AUTHENTICATION_BACKENDS:

    AUTHENTICATION_BACKENDS = [
        "entra_auth.backends.EntraAuthBackend",
        "django.contrib.auth.backends.ModelBackend",  # keep for admin login
    ]
"""

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from .conf import entra_settings
from .graph import GraphError, get_me, get_me_groups

log = logging.getLogger(__name__)

User = get_user_model()


class EntraAuthBackend:
    """
    Authenticate a user from an MSAL result dict.

    Called by ``authenticate(request, msal_result=result)``.
    """

    def authenticate(self, request, *, msal_result: dict | None = None, **kwargs):
        if msal_result is None:
            return None

        if "error" in msal_result:
            log.warning(
                "MSAL error during authentication: %s — %s",
                msal_result.get("error"),
                msal_result.get("error_description", ""),
            )
            return None

        access_token = msal_result.get("access_token")
        claims = msal_result.get("id_token_claims", {})

        if not access_token or not claims:
            log.error("MSAL result missing access_token or id_token_claims")
            return None

        try:
            return self._get_or_create_user(access_token, claims)
        except Exception:
            log.exception("Unexpected error during Entra authentication")
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create_user(self, access_token: str, claims: dict) -> User | None:
        """Resolve (and optionally create) the Django user for this token."""

        # --- Determine username ---
        if entra_settings.USERNAME_FIELD == "oid":
            username = claims.get("oid")
        else:  # "email" (default)
            username = (
                claims.get("preferred_username")
                or claims.get("email")
                or claims.get("upn")
            )

        if not username:
            log.error("Cannot determine username from token claims: %s", claims)
            return None

        # --- Fetch richer profile from Graph ---
        try:
            graph_profile = get_me(
                access_token,
                fields=entra_settings.GRAPH_USER_FIELDS,
            )
        except GraphError:
            log.exception("Could not fetch Graph profile; falling back to claims only")
            graph_profile = {}

        # --- Get or create user ---
        created = False
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            if not entra_settings.CREATE_USERS:
                log.info("User %r not found and CREATE_USERS=False", username)
                return None
            user = User(username=username)
            created = True

        if created or entra_settings.UPDATE_USER_ON_LOGIN:
            self._populate_user(user, claims, graph_profile)
            user.save()
            if created:
                log.info("Created new Entra user: %s", username)

        # --- Group sync ---
        self._sync_groups(user, access_token, claims)

        return user

    def _populate_user(self, user: User, claims: dict, graph_profile: dict) -> None:
        """Copy Graph/token attributes onto the Django user model."""
        email = (
            graph_profile.get("mail")
            or graph_profile.get("userPrincipalName")
            or claims.get("email")
            or claims.get("preferred_username")
            or ""
        )
        user.email = email

        # Standard AbstractUser fields — safe to set even if custom User
        # models don't expose them; worst case is a harmless AttributeError
        _setattr_safe(user, "first_name", graph_profile.get("givenName", ""))
        _setattr_safe(user, "last_name", graph_profile.get("surname", ""))

        # Mark the password unusable so nobody can log in via password
        user.set_unusable_password()

        # Preserve any extra Graph data in a custom field if the model has it
        if hasattr(user, "entra_oid"):
            user.entra_oid = claims.get("oid", "")
        if hasattr(user, "entra_display_name"):
            user.entra_display_name = graph_profile.get("displayName", "")

    def _sync_groups(self, user: User, access_token: str, claims: dict) -> None:
        """Map Entra group memberships to Django groups according to GROUPS_MAP."""
        groups_map: dict = entra_settings.GROUPS_MAP
        if not groups_map:
            return

        # Try token claims first (requires optional-claims config in Entra)
        entra_group_ids: list[str] = claims.get(entra_settings.GROUPS_CLAIM, [])

        # If not in claims (common when group count > 200), fall back to Graph
        if not entra_group_ids:
            try:
                raw = get_me_groups(access_token)
                entra_group_ids = [
                    g.get("id", "") for g in raw if g.get("@odata.type") == "#microsoft.graph.group"
                ]
            except GraphError:
                log.warning("Could not fetch group memberships from Graph")
                return

        desired_django_groups = set()
        for entra_id in entra_group_ids:
            if entra_id in groups_map:
                desired_django_groups.add(groups_map[entra_id])

        current_managed_groups = set(
            user.groups.filter(name__in=groups_map.values()).values_list("name", flat=True)
        )

        to_add = desired_django_groups - current_managed_groups
        to_remove = current_managed_groups - desired_django_groups

        for group_name in to_add:
            group, _ = Group.objects.get_or_create(name=group_name)
            user.groups.add(group)

        if to_remove:
            user.groups.remove(*Group.objects.filter(name__in=to_remove))


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _setattr_safe(obj, attr: str, value) -> None:
    """Set attribute only if the model exposes it (compatible with custom User models)."""
    try:
        if hasattr(obj.__class__, attr):
            setattr(obj, attr, value)
    except Exception:
        pass
