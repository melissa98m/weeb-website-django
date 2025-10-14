"""
Custom DRF authentication that reads JWTs from either:
1) The standard Authorization header (preferred), or
2) A HttpOnly cookie (fallback) whose name is configured in SIMPLE_JWT["AUTH_COOKIE"].
"""

from typing import Optional, Tuple
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.request import Request


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authentication flow:
    - First, try reading the token from the Authorization header (standard "Bearer <jwt>").
    - If no valid header token is found, fall back to the access token stored in a HttpOnly cookie.
      The cookie name is taken from settings.SIMPLE_JWT["AUTH_COOKIE"] (default: "access").

    The return value matches DRF expectations:
      (user, validated_token) on success, or None if no authentication can be performed.

    Errors raised by token parsing/validation are intentionally not swallowed so that DRF can
    return 401 with the appropriate error detail.
    """

    def authenticate(self, request: Request) -> Optional[Tuple[object, object]]:
        # 1)try the Authorization header first (preferred standard)
        header = self.get_header(request)
        if header is not None:
            raw = self.get_raw_token(header)
            if raw is not None:
                # will raise AuthenticationFailed on invalid/expired token
                validated = self.get_validated_token(raw)
                return self.get_user(validated), validated

        # 2) fallback: look for the access token in a HttpOnly cookie
        access_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE", "access")
        raw = request.COOKIES.get(access_cookie_name)
        if raw:
            # vill raise AuthenticationFailed on invalid/expired token
            validated = self.get_validated_token(raw)
            return self.get_user(validated), validated

        # No auth performed (allows other authenticators in the chain, if any)
        return None
