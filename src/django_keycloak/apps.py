from django.apps.config import AppConfig


class KeycloakAppConfig(AppConfig):

    default_auto_field = "django.db.models.BigAutoField"
    name = 'django_keycloak'
    verbose_name = 'Keycloak'
