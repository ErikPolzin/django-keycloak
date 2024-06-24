from datetime import timedelta
import logging
import uuid

from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.conf import settings
from django.utils import timezone

from keycloak import KeycloakOpenID

logger = logging.getLogger(__name__)


class OpenIdConnectProfile(models.Model):
    """OpenID service account profile, usually associated with a client."""

    access_token = models.TextField(null=True)
    expires_before = models.DateTimeField(null=True)
    refresh_token = models.TextField(null=True)
    refresh_expires_before = models.DateTimeField(null=True)
    sub = models.CharField(max_length=255, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name="oidc_profile", on_delete=models.CASCADE
    )

    client = KeycloakOpenID(
        settings.KEYCLOAK_AUTH["URL"],
        settings.KEYCLOAK_AUTH["REALM"],
        settings.KEYCLOAK_AUTH["CLIENT_ID"],
        settings.KEYCLOAK_AUTH["CLIENT_SECRET"],
    )

    @classmethod
    def from_code(cls, code: str, redirect_uri: str = "") -> "OpenIdConnectProfile":
        """Generate or update a OID profile from an authentication code.

        :param realm: Keycloak realm object.
        :param code: Authentication code
        :param redirect_uri
        :rtype: django_keycloak.models.OpenIdConnectProfile
        """
        # Define "initiate_time" before getting the access token to calculate
        # before which time it expires.
        initiate_time = timezone.now()
        token_response = cls.client.token(
            code=code, redirect_uri=redirect_uri, grant_type="authorization_code"
        )
        oidc_profile = cls.from_token_response(token_response)
        oidc_profile.update_tokens(token_response, initiate_time)
        return oidc_profile

    @classmethod
    def from_credentials(
        cls, username: str, password: str, redirect_uri: str = ""
    ) -> "OpenIdConnectProfile":
        """Generate or update a OID profile from user credentials.

        :param realm: Keycloak realm object.
        :param username: Keycloak username
        :param password: Keycloak password
        :param redirect_uri
        :rtype: django_keycloak.models.OpenIdConnectProfile
        """
        initiate_time = timezone.now()
        token_response = cls.client.token(
            username=username,
            password=password,
            redirect_uri=redirect_uri,
            grant_type="password",
        )
        oidc_profile = cls.from_token_response(token_response)
        oidc_profile.update_tokens(token_response, initiate_time)
        return oidc_profile

    @classmethod
    def from_token_response(cls, token_response: dict) -> "OpenIdConnectProfile":
        """Generate an OIDC profile from an auth server response."""
        token_response_key = (
            "id_token" if "id_token" in token_response else "access_token"
        )
        token_object = cls.client.decode_token(token_response[token_response_key])
        # Create the user and profile if they don't exist
        with transaction.atomic():
            User = get_user_model()
            email_field_name = User.get_email_field_name()
            admin_role = getattr(settings, "KEYCLOAK_ADMIN_ROLE", "admin")
            is_superuser = admin_role in token_object.get("realm_access", {}).get(
                "roles", []
            )
            user, _ = User.objects.update_or_create(
                username=token_object.get("preferred_username", token_object["sub"]),
                defaults={
                    email_field_name: token_object.get("email", ""),
                    "first_name": token_object.get("given_name", ""),
                    "last_name": token_object.get("family_name", ""),
                    "is_superuser": is_superuser,
                    "is_staff": is_superuser,
                },
            )
            oidc_profile, _ = cls.objects.get_or_create(
                user=user,
                defaults={
                    "sub": token_object["sub"],
                    "expires_before": token_object["exp"],
                },
            )
        return oidc_profile

    @property
    def is_active(self) -> bool:
        """Check whether this profile has expired."""
        if not self.access_token or not self.expires_before:
            return False
        return self.expires_before > timezone.now()

    @property
    def jwt(self):
        """JS Web Token."""
        if not self.is_active:
            return None
        return self.client.decode_token(self.access_token)

    def update_tokens(self, token_response, initiate_time):
        """Update tokens with data fetched from the auth server.

        :param token_response: Server response
        :param initiate_time: Query init time
        """
        expires_before = initiate_time + timedelta(seconds=token_response["expires_in"])
        refresh_expires_before = initiate_time + timedelta(
            seconds=token_response["refresh_expires_in"]
        )
        # Update the OIDC profile
        self.access_token = token_response["access_token"]
        self.expires_before = expires_before
        self.refresh_token = token_response["refresh_token"]
        self.refresh_expires_before = refresh_expires_before
        self.save()

    def get_active_access_token(self) -> str | None:
        """Get the access token, refreshed if it has expired."""
        initiate_time = timezone.now()
        if (
            self.refresh_expires_before is None
            or initiate_time > self.refresh_expires_before
        ):
            return None
        if initiate_time > self.expires_before:
            # Refresh token
            token_response = self.client.refresh_token(refresh_token=self.refresh_token)
            self.update_tokens(
                token_response=token_response, initiate_time=initiate_time
            )
        return self.access_token

    def entitlement(self) -> dict:
        """Fetch permissions for this realm's client."""
        access_token = self.get_active_access_token()
        resource_id = settings.KEYCLOAK_AUTH["CLIENT_ID"]
        # BUG: This fails with coded 405: Method Not Allowed?
        rpt = self.client.entitlement(access_token, resource_id)["rpt"]
        rpt_decoded = self.client.decode_token(rpt)
        return rpt_decoded


class Nonce(models.Model):
    """Nonce saved in the database."""

    state = models.UUIDField(default=uuid.uuid4, unique=True)
    redirect_uri = models.CharField(max_length=255)
    next_path = models.CharField(max_length=255, null=True)


class KeycloakUser(AbstractUser):
    """A keycloak user copy stored in the database."""
