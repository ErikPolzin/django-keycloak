from datetime import datetime, timedelta
import time
import logging
import uuid

from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.db import models, transaction, connection
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import OperationalError

from keycloak.exceptions import KeycloakError
from keycloak import KeycloakOpenID
from .tools import DEFAULT_CLIENT

logger = logging.getLogger(__name__)


def find_client(client_id: str) -> KeycloakOpenID:
    """Find a client in settings with this client ID, or default."""
    for client_data in settings.KEYCLOAK_CLIENTS.values():
        if client_data["CLIENT_ID"] == client_id:
            return KeycloakOpenID(
                client_data["URL"],
                client_data["REALM"],
                client_data["CLIENT_ID"],
                client_data["CLIENT_SECRET"],
            )
    raise ValueError(f"No client registered with ID '{client_id}'")


def try_while_locked(n, retry_wait=1):
    """Retry a function n times if it throws an operational error.

    In particular, update_or_create seems to lock the table for writes,
    so if two requests come in one after the other with the default sqlite
    database, django throws a 'database is locked' exception.
    """

    def outer(f):
        """Function wrapper."""

        # This only seems to be an issue with sqlite
        if connection.vendor != "sqlite":
            return f

        def inner(*args, **kwargs):
            for i in range(n):
                try:
                    return f(*args, **kwargs)
                except OperationalError as oe:
                    logger.warning("(%s) Encountered an operational error: %s, retrying", i, oe)
                    time.sleep(retry_wait)
            raise OperationalError("Encountered too many operational errors!")

        return inner

    return outer


class OpenIdConnectProfile(models.Model):
    """OpenID service account profile, usually associated with a client."""

    auth_time = models.DateTimeField()
    expires_before = models.DateTimeField()
    access_token = models.TextField(null=True)
    refresh_token = models.TextField(null=True)
    refresh_expires_before = models.DateTimeField(null=True)
    sub = models.CharField(max_length=255, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name="oidc_profile", on_delete=models.CASCADE
    )
    client_id = models.CharField(max_length=100)

    @classmethod
    def from_code(
        cls, code: str, redirect_uri: str = "", client=DEFAULT_CLIENT
    ) -> "OpenIdConnectProfile | None":
        """Generate or update a OID profile from an authentication code.

        :param realm: Keycloak realm object.
        :param code: Authentication code
        :param redirect_uri
        :rtype: django_keycloak.models.OpenIdConnectProfile
        """
        token_response = client.token(
            code=code, redirect_uri=redirect_uri, grant_type="authorization_code"
        )
        profile = cls.from_token(token_response["access_token"], client=client)
        if profile:
            profile.update_tokens(token_response)
        return profile

    @classmethod
    def from_credentials(
        cls, username: str, password: str, redirect_uri: str = "", client=DEFAULT_CLIENT
    ) -> "OpenIdConnectProfile | None":
        """Generate or update a OID profile from user credentials.

        :param realm: Keycloak realm object.
        :param username: Keycloak username
        :param password: Keycloak password
        :param redirect_uri
        :rtype: django_keycloak.models.OpenIdConnectProfile
        """
        token_response = client.token(
            username=username,
            password=password,
            redirect_uri=redirect_uri,
            grant_type="password",
        )
        profile = cls.from_token(token_response["access_token"], client=client)
        if profile:
            profile.update_tokens(token_response)
        return profile

    @classmethod
    @try_while_locked(3)
    def from_token(
        cls, encoded_token: str, client=DEFAULT_CLIENT
    ) -> "OpenIdConnectProfile | None":
        """Generate an OIDC profile from an auth server response."""
        try:
            token = client.decode_token(encoded_token)
        except KeycloakError as e:
            logger.error("Error decoding token: %s", e)
            return None
        # Create the user and profile if they don't exist
        with transaction.atomic():
            User = get_user_model()
            email_field_name = User.get_email_field_name()
            uname = token.get("preferred_username", token["sub"])
            admin_role = getattr(settings, "KEYCLOAK_ADMIN_ROLE", "admin")
            roles = set(token.get("realm_access", {}).get("roles", []))
            # Create new groups if the roles received from keycloak are out of
            # sync with the groups stored in django's database.
            current_roles = set(
                Group.objects.filter(name__in=roles).values_list("name", flat=True)
            )
            new_roles = roles.difference(current_roles)
            if new_roles:
                Group.objects.bulk_create([Group(name=n) for n in new_roles])
            # update_or_create causes issues with sqlite when handling simultaneous
            # requests, but we do need to keep the user data in sync.
            user, created_user = User.objects.prefetch_related(
                "oidc_profile"
            ).update_or_create(
                username=uname,
                defaults={
                    email_field_name: token.get("email", ""),
                    "first_name": token.get("given_name", ""),
                    "last_name": token.get("family_name", ""),
                    "is_superuser": admin_role in roles,
                    "is_staff": admin_role in roles,
                },
            )
            user.groups.set(Group.objects.filter(name__in=roles))
            if created_user:
                logger.info("Created new user '%s' from keycloak server", user.username)
            oidc_profile, _ = cls.objects.update_or_create(
                user=user,
                defaults={
                    "sub": token["sub"],
                    "expires_before": make_aware(datetime.fromtimestamp(token["exp"])),
                    "auth_time": make_aware(datetime.fromtimestamp(token["iat"])),
                    "client_id": token["azp"],
                    # Make sure to reset these values - if this profile has been generated
                    # from an api access token, refreshing will not be available. If it has
                    # been generated from an authorization_code or username/password, the
                    # refresh token will be updated after creation.
                    "refresh_token": None,
                    "refresh_expires_before": None,
                },
            )
        return oidc_profile

    def __str__(self) -> str:
        """Human readable description of an OIDC profile."""
        return f"OpenID profile for {self.user.username} [exp:{self.expires_before}]"

    @property
    def client(self) -> KeycloakOpenID:
        """Get the OpenID client for this profile."""
        return find_client(self.client_id)

    @property
    def can_refresh(self) -> bool:
        """Check whether the profile can refresh its token."""
        return (
            self.refresh_token is not None and self.refresh_expires_before is not None
        )

    def is_expired(self) -> bool:
        """Check whether this profile's token is currently expired."""
        return timezone.now() > self.expires_before

    def refresh_expired(self) -> bool:
        """Check whether the profile's refresh token is expired."""
        # refresh_expired() will return False if there is no refresh token
        if not self.can_refresh:
            return False
        return timezone.now() > self.refresh_expires_before

    def update_tokens(self, token_response: dict) -> None:
        """Update tokens with data fetched from the auth server.

        :param token_response: Server response
        """
        self.access_token = token_response["access_token"]
        refresh_expires_before = self.auth_time + timedelta(
            seconds=token_response["refresh_expires_in"]
        )
        self.refresh_token = token_response["refresh_token"]
        self.refresh_expires_before = refresh_expires_before
        self.save()

    def refresh_if_expired(self) -> bool:
        """Refresh the access token, if expired and refresh is possible."""
        if not self.can_refresh or self.refresh_expired():
            return False
        if self.is_expired():
            # Refresh token
            token_response = self.client.refresh_token(self.refresh_token)
            self.update_tokens(token_response)
            logger.info("Refreshed auth token %s", self.sub)
        return True

    def entitlement(self) -> dict:
        """Fetch permissions for this realm's client."""
        resource_id = self.client.client_id
        # BUG: This fails with coded 405: Method Not Allowed?
        rpt = self.client.entitlement(self.access_token, resource_id)["rpt"]
        rpt_decoded = self.client.decode_token(rpt)
        return rpt_decoded


class Nonce(models.Model):
    """Nonce saved in the database."""

    state = models.UUIDField(default=uuid.uuid4, unique=True)
    redirect_uri = models.CharField(max_length=255)
    next_path = models.CharField(max_length=255, null=True)
