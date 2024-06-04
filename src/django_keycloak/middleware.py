from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, HttpResponse

from django_keycloak.models import Realm


def get_realm(request: HttpRequest) -> Realm | None:
    """Get the first registered realm."""
    if not hasattr(request, "_cached_realm"):
        request._cached_realm = Realm.objects.first()
    return request._cached_realm


class BaseKeycloakMiddleware(MiddlewareMixin):
    """Base Keycloak Middleware,

    Adds realm to the request and sets OIDC cookies.
    """

    set_session_state_cookie = True

    def process_request(self, request: HttpRequest):
        """Adds Realm to request."""
        request.realm = get_realm(request)

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Modify response (see :meth:`set_session_state_cookie_()`)."""
        if self.set_session_state_cookie:
            self.set_session_state_cookie_(request, response)
        return response

    def set_session_state_cookie_(
        self, request: HttpRequest, response: HttpResponse
    ) -> None:
        """Save OIDC session state as cookie in the response."""
        if not request.user.is_authenticated or not hasattr(
            request.user, "oidc_profile"
        ):
            return

        jwt = request.user.oidc_profile.jwt
        if not jwt:
            return

        response.set_cookie(
            "session_state",
            value=jwt["session_state"],
            expires=request.user.oidc_profile.refresh_expires_before,
            httponly=False,
        )
