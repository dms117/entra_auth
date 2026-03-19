"""
entra_auth.backends
~~~~~~~~~~~~~~~~~~~
Custom Django authentication backend tailored for LEO's User model,
which extends models.Model directly rather than AbstractUser.

LEO's User has:
  - username, first_name, last_name, email  (standard fields)
  - groups (ManyToMany to django.contrib.auth.models.Group)
  - is_active, is_staff, is_superuser       (permission flags)
  - last_login                               (DateTimeField)
  - No set_unusable_password / set_password  (stubs that return False)
  - is_authenticated is a @property          (always returns True)

Add to settings.AUTHENTICATION_BACKENDS:

    AUTHENTICATION_BACKENDS = [
        "entra_auth.backends.EntraAuthBackend",
    ]
"""

import logging
from datetime import timezone

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone as django_timezone

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

    def _get_or_create_user(self, access_token: str, claims: dict):
        """Resolve (and optionally create) the LEO User for this token."""

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

        # Entra returns email-style usernames — LEO may store just the local
        # part (before @) or the full UPN. Try full UPN first, then local part.
        user = self._find_user(username)

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
        if user is None:
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

        # --- Update last_login ---
        # Django's auth.login() normally does this but only for AbstractBaseUser.
        # LEO's User has last_login so we update it manually.
        User.objects.filter(pk=user.pk).update(last_login=django_timezone.now())

        # --- Group sync ---
        self._sync_groups(user, access_token, claims)

        return user

    def _find_user(self, username: str):
        """
        Try to find an existing user, adapting the lookup strategy to the
        User model's base class:
    
        AbstractUser / AbstractBaseUser (standard Django):
            1. Full UPN → username  (exact match, most common case)
            2. Full UPN → email     (fallback)
    
        Plain models.Model (custom, e.g. LEO):
            1. Local part → username  (legacy short-username records)
            2. Full UPN  → username   (full UPN records)
            3. Full UPN  → email      (last resort)
    
        The models.Model strategy is more expansive because custom user models
        often have a mixed-format username history from previous auth systems.
        """
        from django.contrib.auth.base_user import AbstractBaseUser
    
        local = username.split("@")[0] if "@" in username else username
        is_standard = isinstance(User(), AbstractBaseUser)
    
        if is_standard:
            # Standard Django User — usernames are typically stored exactly as
            # the identity provider returns them, so try exact match first.
    
            # 1. Full UPN → username
            try:
                return User.objects.get(username=username)
            except User.DoesNotExist:
                pass
    
            # 2. Full UPN → email
            if "@" in username:
                try:
                    return User.objects.get(email=username)
                except User.DoesNotExist:
                    pass
    
        else:
            # Custom models.Model User — may have mixed username formats from
            # legacy auth systems, so try local part first.
    
            # 1. Local part → username (handles legacy short-username records)
            try:
                return User.objects.get(username=local)
            except User.DoesNotExist:
                pass
    
            # 2. Full UPN → username (handles full UPN records)
            if "@" in username:
                try:
                    return User.objects.get(username=username)
                except User.DoesNotExist:
                    pass
    
            # 3. Full UPN → email (last resort)
            if "@" in username:
                try:
                    return User.objects.get(email=username)
                except User.DoesNotExist:
                    pass
    
        return None

    def _populate_user(self, user, claims: dict, graph_profile: dict) -> None:
        """
        Copy Graph / token attributes onto the LEO User.
        Only sets fields that actually exist on the model.
        """
        email = (
            graph_profile.get("mail")
            or graph_profile.get("userPrincipalName")
            or claims.get("email")
            or claims.get("preferred_username")
            or ""
        )

        # These fields all exist on LEO's User model
        user.email = email
        user.first_name = graph_profile.get("givenName") or user.first_name or ""
        user.last_name = graph_profile.get("surname") or user.last_name or ""

        # Ensure the account is active on login
        # (don't override if an admin has explicitly deactivated it)
        if not user.pk:
            # Only set default for new users
            user.is_active = True

    def _sync_groups(self, user, access_token: str, claims: dict) -> None:
        """Map Entra group memberships to LEO Django groups via GROUPS_MAP."""
        groups_map: dict = entra_settings.GROUPS_MAP
        if not groups_map:
            return

        # Try token claims first
        entra_group_ids: list[str] = claims.get(entra_settings.GROUPS_CLAIM, [])

        # Fall back to Graph if not in claims (happens when user is in 200+ groups)
        if not entra_group_ids:
            try:
                raw = get_me_groups(access_token)
                entra_group_ids = [
                    g.get("id", "")
                    for g in raw
                    if g.get("@odata.type") == "#microsoft.graph.group"
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