import logging

from django.conf import settings
from django.http import HttpRequest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db.models import Model
from django.core.exceptions import ImproperlyConfigured
from keycloak.exceptions import KeycloakError

from .models import OpenIdConnectProfile


logger = logging.getLogger(__name__)


class KeycloakAuthorizationBase:
    """Base Keycloak Authorization backend."""

    def get_user(self, user_id: int) -> User | None:
        """Get user if profile hasn't expired, else None.

        :param user_id: User PK
        :return: User or None
        """
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        try:
            valid = user.oidc_profile.refresh_if_expired()
            if not valid:
                return None
        except OpenIdConnectProfile.DoesNotExist:
            return None
        return user

    def get_all_permissions(self, user_obj: User, obj: Model | None = None) -> set[str]:
        """Get and cache all permissions for a given user.

        :param user_obj: User
        :param obj: _description_, defaults to None
        :return: Set of user permissions
        """
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return set()
        if not hasattr(user_obj, "_keycloak_perm_cache"):
            user_obj._keycloak_perm_cache = self.get_keycloak_permissions(user_obj)
        return user_obj._keycloak_perm_cache

    def get_keycloak_permissions(self, user_obj: User) -> set[str]:
        """Get all permissions for a given user.

        :param user_obj: User
        :param obj: _description_, defaults to None
        :return: Set of user permissions
        """
        if not hasattr(user_obj, "oidc_profile"):
            return set()

        # TODO: Fix the entitlement function
        rpt_decoded = user_obj.oidc_profile.entitlement()
        perm_method = getattr(settings, 'KEYCLOAK_PERMISSIONS_METHOD', "role")

        if perm_method == "role":
            client_id = settings.KEYCLOAK_AUTH["CLIENT_ID"],
            role_data = rpt_decoded["resource_access"].get(client_id, {"roles": []})
            return {role for role in role_data["roles"]}
        elif perm_method == "resource":
            permissions = set()
            for p in rpt_decoded["authorization"].get("permissions", []):
                if "scopes" in p:
                    for scope in p["scopes"]:
                        if "." in p["resource_set_name"]:
                            app, model = p["resource_set_name"].split(".", 1)
                            permissions.add(f"{app}.{scope}_{model}")
                        else:
                            permissions.add(f"{scope}_{p['resource_set_name']}")
                else:
                    permissions.add(p["resource_set_name"])
            return permissions
        else:
            raise ImproperlyConfigured(
                f"Unsupported permission method configured for Keycloak: {perm_method}"
            )

    def has_perm(self, user_obj: User, perm: str, obj: Model | None = None) -> bool:
        """Check whether a user has a permission.

        :param user_obj: User
        :param perm: Permission
        :param obj: Model object, defaults to None
        """
        if not user_obj.is_active:
            return False
        granted_perms = self.get_all_permissions(user_obj, obj)
        return perm in granted_perms


class KeycloakAuthorizationCodeBackend(KeycloakAuthorizationBase):
    """Authenticates users with an access token."""

    def authenticate(self,
                     request: HttpRequest,
                     code: str,
                     redirect_uri: str = "") -> User | None:
        """Authenticate a user from an access code."""
        try:
            profile = OpenIdConnectProfile.from_code(code, redirect_uri)
        except KeycloakError as e:
            logger.error("Error with sign-in: %s", e)
            return None
        return profile.user


class KeycloakPasswordCredentialsBackend(KeycloakAuthorizationBase):

    def authenticate(self,
                     request: HttpRequest,
                     username: str,
                     password: str,
                     redirect_uri: str = "") -> User:
        """Authenticate a user using username/password."""
        try:
            profile = OpenIdConnectProfile.from_credentials(username, password, redirect_uri)
        except KeycloakError as e:
            logger.error("Error with sign-in: %s", e)
            return None
        return profile.user
