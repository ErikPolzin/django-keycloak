from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import KeycloakUser, OpenIdConnectProfile


admin.site.register(KeycloakUser, UserAdmin)
admin.site.register(OpenIdConnectProfile)
