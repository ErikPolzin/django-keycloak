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
pip install django-keycloak-admin
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
    'django_keycloak.backends.KeycloakAuthorizationCodeBackend',
]
AUTH_USER_MODEL = "django_keycloak.KeycloakUser"  # Optional
KEYCLOAK_CLIENTS = {
    "DEFAULT": {
        "URL": ...,
        "REALM": "example-realm",
        "CLIENT_ID": "example-backend-client",
        "CLIENT_SECRET": "*************************",
    },
    # If you're using django's REST framework
    "API": {
        "URL": "http://localhost:8001",
        "REALM": "example-realm",
        "CLIENT_ID": "example-frontend-client",
        "CLIENT_SECRET": None,  # Typically a public client
    },
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_keycloak.authentication.KeycloakDRFAuthentication',
    ]
}
```
3. Include URLs
Open your app's `urls.py` file, ad add the following:
```python
from django.contrib import admin
from django.urls import path, include
from django_keycloak.views import admin_login

urlpatterns = [
    # This will override the default django login page
    path("admin/", include("django_keycloak.urls")),
    path("admin/", admin.site.urls),
    ...
]
```
4. Migrate changes:
```bash
python manage.py migrate
```

## Roles and Permissions

Syncing permissions with Keycloak isn't currently supported, but django_keycloak is able to recognise a special 'superuser' role defined by `KEYCLOAK_ADMIN_ROLE` defined in settings (and defaulting to 'admin'). If users have this role, they are classified a django superuser. Without this role, they may not be able to access the admin site.

## Examples

An example application demonstrating this setup is included in the `examples` folder.
