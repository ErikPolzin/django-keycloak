import logging

from django.http import HttpRequest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
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
        return profile.user if profile else None


class KeycloakPasswordCredentialsBackend(KeycloakAuthorizationBase):
    """Authenticates users with a username and password."""

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
        return profile.user if profile else None
