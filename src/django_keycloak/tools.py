from django.conf import settings
from django.contrib.auth.models import User
from keycloak import KeycloakAdmin, KeycloakOpenID


default_conf = settings.KEYCLOAK_CLIENTS["DEFAULT"]
DEFAULT_CLIENT = KeycloakOpenID(
    server_url=default_conf["URL"],
    realm_name=default_conf["REALM"],
    client_id=default_conf["CLIENT_ID"],
    client_secret_key=default_conf["CLIENT_SECRET"],
)


if "ADMIN" in settings.KEYCLOAK_CLIENTS:
    admin_conf = settings.KEYCLOAK_CLIENTS["ADMIN"]
    ADMIN_CLIENT = KeycloakAdmin(
        server_url=default_conf["URL"],
        username=admin_conf["USERNAME"],
        password=admin_conf["PASSWORD"],
        user_realm_name=admin_conf.get("REALM", "master"),
        realm_name=default_conf["REALM"],
    )
else:
    ADMIN_CLIENT = None


def create_keycloak_user(user: User, password: str | None = None):
    """Create a keycloak user from a Django user."""
    if not ADMIN_CLIENT:
        raise ValueError("Cannot create a user, the admin client is not configured")
    credentials = []
    if password:
        credentials.append({"type": "password", "value": password})
    ADMIN_CLIENT.create_user(
        {
            "email": user.email,
            "username": user.username,
            "enabled": user.is_active,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "credentials": credentials,
        }
    )
