from datetime import timedelta
import logging
import uuid

from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.conf import settings
from django.utils import timezone
from django.utils.functional import cached_property

from keycloak import KeycloakOpenID

logger = logging.getLogger(__name__)


class Realm(models.Model):
    """Keycloak realm data."""

    server = models.CharField(max_length=255)
    name = models.CharField(
        max_length=255,
        unique=True,
        help_text=(
            "Name as known on the Keycloak server. "
            "This name is used in the API paths "
            "of this Realm."
        ),
    )
    clients: list["Client"]

    def __str__(self) -> str:
        return f"Realm: {self.name}"


class Client(models.Model):
    """A realm's client."""

    realm = models.ForeignKey(Realm, related_name="clients", on_delete=models.CASCADE)
    client_id = models.CharField(max_length=255)
    secret = models.CharField(max_length=255, null=True, blank=True)

    @classmethod
    def get_default(cls) -> "Client":
        if hasattr(settings, "KEYCLOAK_CLIENT_DEFAULT"):
            return cls.objects.get(client_id=settings.KEYCLOAK_CLIENT_DEFAULT)
        return cls.objects.first()

    @cached_property
    def openid_client(self) -> KeycloakOpenID:
        """Return keykloak OpenID client."""
        return KeycloakOpenID(
            self.realm.server, self.realm.name, self.client_id, self.secret
        )

    def __str__(self) -> str:
        return f"Client: {self.client_id}"


class OpenIdConnectProfile(models.Model):
    """OpenID service account profile, usually associated with a client."""

    access_token = models.TextField(null=True)
    expires_before = models.DateTimeField(null=True)
    refresh_token = models.TextField(null=True)
    refresh_expires_before = models.DateTimeField(null=True)
    sub = models.CharField(max_length=255, unique=True)
    client = models.ForeignKey(
        Client, related_name="openid_profiles", on_delete=models.CASCADE
    )
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name="oidc_profile", on_delete=models.CASCADE
    )

    @classmethod
    def from_code(
        cls, client: Client, code: str, redirect_uri: str = ""
    ) -> "OpenIdConnectProfile":
        """Generate or update a OID profile from an authentication code.

        :param realm: Keycloak realm object.
        :param code: Authentication code
        :param redirect_uri
        :rtype: django_keycloak.models.OpenIdConnectProfile
        """
        # Define "initiate_time" before getting the access token to calculate
        # before which time it expires.
        initiate_time = timezone.now()
        token_response = client.openid_client.token(
            code=code, redirect_uri=redirect_uri, grant_type="authorization_code"
        )
        oidc_profile = cls.from_token_response(client, token_response)
        oidc_profile.update_tokens(token_response, initiate_time)
        return oidc_profile

    @classmethod
    def from_credentials(
        cls, client: Client, username: str, password: str, redirect_uri: str = ""
    ) -> "OpenIdConnectProfile":
        """Generate or update a OID profile from user credentials.

        :param realm: Keycloak realm object.
        :param username: Keycloak username
        :param password: Keycloak password
        :param redirect_uri
        :rtype: django_keycloak.models.OpenIdConnectProfile
        """
        initiate_time = timezone.now()
        token_response = client.openid_client.token(
            username=username, password=password, redirect_uri=redirect_uri, grant_type="password"
        )
        oidc_profile = cls.from_token_response(client, token_response)
        oidc_profile.update_tokens(token_response, initiate_time)
        return oidc_profile

    @classmethod
    def from_token_response(cls, client: Client, token_response: dict) -> "OpenIdConnectProfile":
        """Generate an OIDC profile from an auth server response."""
        token_response_key = (
            "id_token" if "id_token" in token_response else "access_token"
        )
        token_object = client.openid_client.decode_token(
            token_response[token_response_key]
        )
        # Create the user and profile if they don't exist
        with transaction.atomic():
            User = get_user_model()
            email_field_name = User.get_email_field_name()
            admin_role = getattr(settings, 'KEYCLOAK_ADMIN_ROLE', "admin")
            is_superuser = admin_role in token_object.get("realm_access", {}).get("roles", [])
            user, _ = User.objects.update_or_create(
                username=token_object.get("preferred_username", token_object["sub"]),
                defaults={
                    email_field_name: token_object.get("email", ""),
                    "first_name": token_object.get("given_name", ""),
                    "last_name": token_object.get("family_name", ""),
                    "is_superuser": is_superuser,
                    "is_staff": is_superuser
                },
            )
            oidc_profile, _ = OpenIdConnectProfile.objects.get_or_create(
                sub=token_object["sub"], defaults={"client": client, "user": user}
            )
        return oidc_profile

    @property
    def openid_client(self) -> KeycloakOpenID:
        """This profile's realm's OpenID API client."""
        return self.client.openid_client

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
        return self.openid_client.decode_token(self.access_token)

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
            token_response = self.openid_client.refresh_token(
                refresh_token=self.refresh_token
            )
            self.update_tokens(
                token_response=token_response, initiate_time=initiate_time
            )
        return self.access_token

    def entitlement(self) -> dict:
        """Fetch permissions for this realm's client."""
        access_token = self.get_active_access_token()
        resource_id = self.client.client_id
        # BUG: This fails with coded 405: Method Not Allowed?
        rpt = self.openid_client.entitlement(access_token, resource_id)["rpt"]
        rpt_decoded = self.openid_client.decode_token(rpt)
        return rpt_decoded


class Nonce(models.Model):
    """Nonce saved in the database."""

    state = models.UUIDField(default=uuid.uuid4, unique=True)
    redirect_uri = models.CharField(max_length=255)
    next_path = models.CharField(max_length=255, null=True)


class KeycloakUser(AbstractUser):
    """A keycloak user copy stored in the database."""
