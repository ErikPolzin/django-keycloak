from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import KeycloakUser, Realm, Client


admin.site.register(KeycloakUser, UserAdmin)
admin.site.register(Realm)
admin.site.register(Client)
