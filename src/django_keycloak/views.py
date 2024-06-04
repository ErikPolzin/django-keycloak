import logging

from django.shortcuts import resolve_url
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http.response import (
    HttpResponseBadRequest,
    HttpResponseServerError,
    HttpResponseRedirect,
    JsonResponse
)
from django.urls.base import reverse
from django.views.generic.base import RedirectView

from .models import Nonce


logger = logging.getLogger(__name__)


class Login(RedirectView):
    """Login View."""

    def get(self, request, *args, **kwargs):
        if request.realm is None:
            return JsonResponse({"error": "No Realm configured"}, status=500)
        return super().get(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        """Redirects to the OIDC authorization URL."""

        nonce = Nonce.objects.create(
            redirect_uri=self.request.build_absolute_uri(
                location=reverse("keycloak_login_complete")
            ),
            next_path=self.request.GET.get("next"),
        )

        self.request.session["oidc_state"] = str(nonce.state)

        authorization_url = self.request.realm.openid_api_client.auth_url(
            redirect_uri=nonce.redirect_uri, state=str(nonce.state)
        )

        return authorization_url


class LoginComplete(RedirectView):
    """Login Complete View."""

    def get(self, *args, **kwargs):
        request = self.request

        if "error" in request.GET:
            return HttpResponseServerError(request.GET["error"])

        if "code" not in request.GET and "state" not in request.GET:
            return HttpResponseBadRequest()

        if (
            "oidc_state" not in request.session
            or request.GET["state"] != request.session["oidc_state"]
        ):
            # Missing or incorrect state; login again.
            return HttpResponseRedirect(reverse("keycloak_login"))

        nonce = Nonce.objects.get(state=request.GET["state"])
        user = authenticate(
            request=request, code=request.GET["code"], redirect_uri=nonce.redirect_uri
        )
        login(request, user)
        nonce.delete()
        return HttpResponseRedirect(nonce.next_path or "/")


class Logout(RedirectView):
    """Logout View."""

    def get_redirect_url(self, *args, **kwargs):
        if hasattr(self.request.user, "oidc_profile"):
            self.request.realm.openid_api_client.logout(
                self.request.user.oidc_profile.refresh_token
            )
            self.request.user.oidc_profile.access_token = None
            self.request.user.oidc_profile.expires_before = None
            self.request.user.oidc_profile.refresh_token = None
            self.request.user.oidc_profile.refresh_expires_before = None
            self.request.user.oidc_profile.save()

        logout(self.request)

        if settings.LOGOUT_REDIRECT_URL:
            return resolve_url(settings.LOGOUT_REDIRECT_URL)

        return reverse("keycloak_login")
