"""
URL configuration for resource_provider_api project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

from . import views

urlpatterns = [
    path("admin/login/", lambda _: redirect("keycloak_login")),
    path("admin/", admin.site.urls),
    path("keycloak/", include("django_keycloak.urls")),
    path("api/end-point/", views.api_end_point),
    path("api/authenticated-end-point/", views.authenticated_end_point),
]
