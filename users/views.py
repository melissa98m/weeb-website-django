"""
JWT cookie-based authentication views for the API.
"""

from django.conf import settings
from django.http import JsonResponse
from django.middleware import csrf
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email as dj_validate_email

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import MeSerializer

User = get_user_model()


def _cookie_settings():
    """
    Read cookie behavior (names and flags) from SIMPLE_JWT settings.

    Notes:
    - Keep AUTH_COOKIE_HTTP_ONLY=True to avoid JS access (XSS mitigation).
    - Keep AUTH_COOKIE_SECURE=True in production so cookies only travel over HTTPS.
    - Consider setting the domain if you need cross-subdomain cookies (e.g. .example.com).
    - SameSite=Lax is usually safe for typical app flows (protects against CSRF on top-level
      navigations). Adjust to 'Strict' or 'None' (with Secure) depending on your needs.
    """
    cfg = settings.SIMPLE_JWT
    return {
        "secure": cfg.get("AUTH_COOKIE_SECURE", True),
        "httponly": cfg.get("AUTH_COOKIE_HTTP_ONLY", True),
        "samesite": cfg.get("AUTH_COOKIE_SAMESITE", "Lax"),
        "access_name": cfg.get("AUTH_COOKIE", "access"),
        "refresh_name": cfg.get("AUTH_COOKIE_REFRESH", "refresh"),
    }


class CookieTokenObtainPairView(TokenObtainPairView):
    """
    Issue JWT access and refresh tokens and set them as cookies.

    Request body:
      {
        "username": "<username>",
        "password": "<password>"
      }

    Response:
      200 OK { "detail": "logged_in" }
      (Tokens are *not* returned in the body; they are written to cookies.)

    Security notes:
    - Cookies are HttpOnly and (in prod) Secure to reduce XSS/mitm risk.
    - Do not include the tokens in the JSON payload.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        data = response.data
        access = data.get("access")
        refresh = data.get("refresh")
        # On error (e.g., wrong credentials), DRF returns 401 and no tokens.
        if not access or not refresh:
            return response

        opts = _cookie_settings()
        # Write tokens to cookies; do not return them in the response body.
        response.set_cookie(
            key=opts["access_name"],
            value=access,
            secure=opts["secure"],
            httponly=opts["httponly"],
            samesite=opts["samesite"],
        )
        response.set_cookie(
            key=opts["refresh_name"],
            value=refresh,
            secure=opts["secure"],
            httponly=opts["httponly"],
            samesite=opts["samesite"],
        )
        response.data = {"detail": "logged_in"}
        return response


class CookieTokenRefreshView(TokenRefreshView):
    """
    Refresh the access token from the refresh token.

    Behavior:
    - If "refresh" is present in request.data, use it.
    - Otherwise, fall back to the HttpOnly refresh cookie.
    - On success, set a new access cookie and return { "detail": "refreshed" }.

    Response:
      200 OK { "detail": "refreshed" }
      401 Unauthorized if the refresh token is invalid or expired.

    Security notes:
    - Keep short access lifetime; refresh lifetime can be longer.
    - If you enable rotation and blacklisting, ensure the blacklist app is installed.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        opts = _cookie_settings()
        # Allow body-provided refresh token (standard), else fall back to cookie.
        if not request.data.get("refresh"):
            cookie_val = request.COOKIES.get(opts["refresh_name"])
            if cookie_val:
                request.data["refresh"] = cookie_val

        response = super().post(request, *args, **kwargs)
        access = response.data.get("access")
        if access:
            # Write the new access token to the cookie and hide raw token from body.
            response.set_cookie(
                key=opts["access_name"],
                value=access,
                secure=opts["secure"],
                httponly=opts["httponly"],
                samesite=opts["samesite"],
            )
            response.data = {"detail": "refreshed"}
        return response


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    """
    Log the user out by instructing the browser to delete the JWT cookies.

    Response:
      200 OK { "detail": "logged_out" }

    Notes:
    - Deletion is done via Set-Cookie with expired attributes (idempotent).
    - If you use refresh rotation + blacklist, you can also blacklist the token here.
    """
    opts = _cookie_settings()
    resp = Response({"detail": "logged_out"})
    resp.delete_cookie(opts["access_name"], samesite=opts["samesite"])
    resp.delete_cookie(opts["refresh_name"], samesite=opts["samesite"])
    return resp


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me_view(request):
    """
    Return the authenticated user's profile.

    Response:
      200 OK {
        "id": <int>,
        "username": "<str>",
        "email": "<str>",
        "first_name": "<str>",
        "last_name": "<str>"
      }
      401 Unauthorized if not authenticated.
    """
    return Response(MeSerializer(request.user).data)


@api_view(["GET"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def csrf_view(request):
    """
    Ensure a CSRF cookie is set and also return its value as JSON for convenience.

    Response:
      200 OK { "csrfToken": "<str>" }

    Frontend:
    - Read the 'csrftoken' cookie and send it as 'X-CSRFToken' header on mutating requests.
    - Keep CSRF_COOKIE_SECURE=True in production with HTTPS.
    """
    token = csrf.get_token(request)
    return JsonResponse({"csrfToken": token})


@api_view(["GET"])
@permission_classes([AllowAny])
def health_view(request):
    """
    Lightweight health check endpoint.
    Response:
      200 OK { "ok": true, "version": "v3-tests" }
    """
    return Response({"ok": True, "version": "v3-tests"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    """
    Create a new user account and log them in by setting JWT cookies.

    Request body (all fields required):
      {
        "username": "<str>",
        "email": "<str>",            # validated + unique (case-insensitive)
        "first_name": "<str>",
        "last_name": "<str>",
        "password": "<str>",
        "password_confirm": "<str>"  # must match password
      }

    Responses:
      201 Created { "detail": "registered" }  # cookies 'access' and 'refresh' are set
      400 Bad Request with field-level errors if validation fails.

    Security notes:
    - Password is validated using Django's built-in validators (robustness policy).
    - Tokens are written as HttpOnly cookies; no token leakage in response body.
    """
    data = request.data or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    password = data.get("password") or ""
    password_confirm = data.get("password_confirm") or ""

    errors = {}
    # Required fields
    for field, value in [
        ("username", username),
        ("email", email),
        ("first_name", first_name),
        ("last_name", last_name),
        ("password", password),
        ("password_confirm", password_confirm),
    ]:
        if not value:
            errors.setdefault(field, []).append("Requis.")

    # Password confirmation
    if password and password_confirm and password != password_confirm:
        errors.setdefault("password_confirm", []).append("Ne correspond pas au mot de passe.")

    # Username uniqueness (case-insensitive)
    if username and User.objects.filter(username__iexact=username).exists():
        errors.setdefault("username", []).append("Déjà pris.")

    # Email validation + uniqueness (case-insensitive)
    if email:
        try:
            dj_validate_email(email)
        except Exception:
            errors.setdefault("email", []).append("Format email invalide.")
        else:
            if User.objects.filter(email__iexact=email).exists():
                errors.setdefault("email", []).append("Déjà utilisé.")

    if errors:
        # Return aggregated field-level errors with 400
        return Response(errors, status=status.HTTP_400_BAD_REQUEST)

    # Enforce Django password validators (length, common, numeric-only, etc.)
    try:
        validate_password(password)
    except DjangoValidationError as e:
        return Response({"password": list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

    # Create the user record
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
    )

    # Auto-login: mint tokens and set them as cookies
    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    opts = _cookie_settings()
    resp = Response({"detail": "registered"}, status=status.HTTP_201_CREATED)
    resp.set_cookie(
        key=opts["access_name"],
        value=access,
        secure=opts["secure"],
        httponly=opts["httponly"],
        samesite=opts["samesite"],
    )
    resp.set_cookie(
        key=opts["refresh_name"],
        value=str(refresh),
        secure=opts["secure"],
        httponly=opts["httponly"],
        samesite=opts["samesite"],
    )
    return resp
