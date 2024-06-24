from rest_framework.authentication import BaseAuthentication
from django.contrib.auth import get_user_model
from django.conf import settings
from keycloak import KeycloakOpenID


class KeycloakDRFAuthentication(BaseAuthentication):
    """Authentication backend for rest framework."""

    client = KeycloakOpenID(
        settings.DRF_KEYCLOAK_AUTH["URL"],
        settings.DRF_KEYCLOAK_AUTH["REALM"],
        settings.DRF_KEYCLOAK_AUTH["CLIENT_ID"],
        settings.DRF_KEYCLOAK_AUTH["CLIENT_SECRET"],
    )

    def authenticate(self, request):
        auth = request.META.get("HTTP_AUTHORIZATION")
        if not auth:
            return None
        auth_parts = auth.split()
        if not len(auth_parts) > 1:
            return None
        token_object = self.client.decode_token(auth_parts[1])
        UserModel = get_user_model()
        uname = token_object.get("preferred_username", token_object["sub"])
        user, _ = UserModel.objects.get_or_create(username=uname)
        return (user, None)
