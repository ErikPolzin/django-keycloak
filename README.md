# Django Keycloak

A simple remote authentication module for use with Django and a Keycloak auth server.

Loosely based on Peter Slump's unmaintained `https://github.com/Peter-Slump/django-keycloak`. This updated version works with Keycloak v21.0, Django 5.0.0 and python-keycloak 4.0.0.

## Capabilities

It supports:

- OpenID authentication for logging into Django's admin interface
- Authentication for REST requests, using django-rest-framework

TODO: Support resource & role permissions

## Quickstart

1. Install via pip:
```bash
pip install git+https://github.com/ErikPolzin/django-keycloak.git
```
2. Configure settings:
In your application's settings, add the following lines:
```python
# your-project/settings.py
INSTALLED_APPS = [
    ...
    'django_keycloak'
]
# For admin site authentication
AUTHENTICATION_BACKENDS = [
    ...
    'django_keycloak.auth.backends.KeycloakAuthorizationCodeBackend',
]
AUTH_USER_MODEL = "django_keycloak.KeycloakUser"
LOGIN_URL = 'keycloak_login'
KEYCLOAK_CLIENT_DEFAULT = ...  # Client ID of the default keycloak client
# If you're using django's REST framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_keycloak.backends.KeycloakDRFAuthentication',
    ]
}
KEYCLOAK_CLIENT_API = ...  # Client ID of the API keycloak client
```
3. Migrate changes:
```bash
python manage.py migrate
```
4. Setup a realm:
Run the custom Django command
```bash
python manage.py set_realm <realm_name>
```
and follow the prompts to setup a new realm. Make sure to add at least one client with
```bash
python manage.py add_client <realm_name>
```

## Roles and Permissions

Syncing permissions with Keycloak isn't currently supported, but django_keycloak is able to recognise a special 'superuser' role defined by `KEYCLOAK_ADMIN_ROLE` defined in settings (and defaulting to 'admin'). If users have this role, they are classified a django superuser. Without this role, they may not be able to access the admin site.

## Examples

An example application demonstrating this setup is included in the `examples` folder.
