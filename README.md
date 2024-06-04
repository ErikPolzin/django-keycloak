# Django Keycloak

A simple remote authentication module for use with Django and a Keycloak auth server.

Loosely based on Peter Slump's unmaintained `https://github.com/Peter-Slump/django-keycloak`. This updated version works with Keycloak v21.0, Django 5.0.0 and python-keycloak 4.0.0.

## Capabilities

It supports:

- OpenID authentication
- Syncing to local user copies in Django's auth user table (for admin site access).

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
MIDDLEWARE = [
    ...
    'django_keycloak.middleware.BaseKeycloakMiddleware',
]

AUTHENTICATION_BACKENDS = [
    ...
    'django_keycloak.auth.backends.KeycloakAuthorizationCodeBackend',
]
AUTH_USER_MODEL = "django_keycloak.KeycloakUser"
LOGIN_URL = 'keycloak_login'
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
and follow the prompts to register an auth server, client and realm for your API.

## Examples

An example application demonstrating this setup is included in the `examples` folder.
