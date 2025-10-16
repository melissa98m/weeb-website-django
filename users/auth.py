"""
Custom DRF authentication that reads JWTs from either:
1) The standard Authorization header (preferred), or
2) An HttpOnly cookie (fallback) whose name is configured in SIMPLE_JWT["AUTH_COOKIE"].
"""
from typing import Optional, Tuple
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.request import Request

class CookieJWTAuthentication(JWTAuthentication):
    """
    Authentication flow:
    - First, try reading the token from the Authorization header (standard "Bearer <jwt>").
    - If no valid header token is found, fall back to the access token stored in an HttpOnly cookie.
      The cookie name is taken from settings.SIMPLE_JWT["AUTH_COOKIE"] (default: "access").

    Returns:
      (user, validated_token) on success, or None if no authentication can be performed.
    """

    def authenticate(self, request: Request) -> Optional[Tuple[object, object]]:
        # 1) Try the Authorization header first (preferred standard)
        header = self.get_header(request)
        if header is not None:
            raw = self.get_raw_token(header)
            if raw is not None:
                # will raise AuthenticationFailed on invalid/expired token
                validated = self.get_validated_token(raw)
                return self.get_user(validated), validated

        # 2) Fallback: look for the access token in an HttpOnly cookie
        access_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE", "access")
        raw = request.COOKIES.get(access_cookie_name)
        if raw:
            # will raise AuthenticationFailed on invalid/expired token
            validated = self.get_validated_token(raw)
            return self.get_user(validated), validated

        # No auth performed (allows other authenticators in the chain, if any)
        return None
