import logging

from rest_framework.authentication import BaseAuthentication
from django.conf import settings
from keycloak import KeycloakOpenID
from .models import OpenIdConnectProfile

logger = logging.getLogger(__file__)


if "API" in settings.KEYCLOAK_CLIENTS:
    API_CLIENT = KeycloakOpenID(
        settings.KEYCLOAK_CLIENTS["API"]["URL"],
        settings.KEYCLOAK_CLIENTS["API"]["REALM"],
        settings.KEYCLOAK_CLIENTS["API"]["CLIENT_ID"],
        settings.KEYCLOAK_CLIENTS["API"]["CLIENT_SECRET"],
    )
else:
    API_CLIENT = None


class KeycloakDRFAuthentication(BaseAuthentication):
    """Authentication backend for rest framework."""

    def authenticate(self, request):
        auth = request.META.get("HTTP_AUTHORIZATION")
        if not auth:
            return None
        auth_parts = auth.split()
        if not len(auth_parts) > 1:
            return None
        profile = OpenIdConnectProfile.from_token(auth_parts[1], client=API_CLIENT)
        if not profile:
            return None
        return (profile.user, profile)
