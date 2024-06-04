from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import KeycloakUser


admin.site.register(KeycloakUser, UserAdmin)
