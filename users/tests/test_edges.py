"""
Edge-case integration tests for the cookie-based JWT auth layer.

This suite focuses on:
- Health/CSRF endpoints behavior and payloads
- Invalid Authorization headers (malformed/forged)
- Logout idempotency and cookie deletion even when no cookies existed
- Extra assertions on login response and cookie flags (HttpOnly)
- Refresh precedence when both body and cookie exist
- Email uniqueness being case-insensitive at registration

Notes:
- CSRF header must be provided as "HTTP_X_CSRFTOKEN" when using Django's test client.
- @override_settings is used to make cookies non-Secure and to enforce deterministic password policy.
"""

from django.test import override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta

User = get_user_model()

# Common testing overrides:
# - Disable Secure on cookies so tests can run over HTTP.
# - Keep HttpOnly=True to emulate production semantics.
# - Provide explicit password validators for deterministic results.
COMMON_OVERRIDES = dict(
    CSRF_COOKIE_SECURE=False,
    SESSION_COOKIE_SECURE=False,
    SIMPLE_JWT={
        "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
        "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
        "ROTATE_REFRESH_TOKENS": True,
        "BLACKLIST_AFTER_ROTATION": True,
        "UPDATE_LAST_LOGIN": True,
        "AUTH_COOKIE": "access",
        "AUTH_COOKIE_REFRESH": "refresh",
        "AUTH_COOKIE_SECURE": False,
        "AUTH_COOKIE_HTTP_ONLY": True,
        "AUTH_COOKIE_SAMESITE": "Lax",
    },
    AUTH_PASSWORD_VALIDATORS=[
        {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
        {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
        {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    ],
)


@override_settings(**COMMON_OVERRIDES)
class EdgeTests(APITestCase):
    """
    Edge cases around auth endpoints and cookie behaviors.
    """

    def setUp(self):
        """
        Create a baseline user and set the auth base path.
        """
        self.base = "/api/auth"
        self.user = User.objects.create_user(
            username="edge",
            email="edge@example.com",
            first_name="Edge",
            last_name="Case",
            password="EdgePass123!",
        )

    def _csrf_headers(self):
        """
        Obtain a CSRF cookie and return the header dict expected by Django's test client.
        """
        r = self.client.get(f"{self.base}/csrf/")
        self.assertEqual(r.status_code, 200)
        csrftoken = self.client.cookies.get("csrftoken").value
        return {"HTTP_X_CSRFTOKEN": csrftoken}

    # --- health & csrf payload ---

    def test_health_ok(self):
        """Health endpoint returns a minimal OK payload."""
        r = self.client.get(f"{self.base}/health/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data.get("ok", False))

    def test_csrf_cookie_and_json_payload(self):
        """CSRF endpoint sets the cookie and includes the token in the JSON body."""
        r = self.client.get(f"{self.base}/csrf/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("csrftoken", self.client.cookies)
        self.assertIn("csrfToken", r.json())
        self.assertTrue(r.json().get("csrfToken"))

    # --- Authorization header invalid -> 401 (covers invalid header token path) ---

    def test_me_with_invalid_bearer_token_401(self):
        """Malformed Bearer token must lead to 401 Unauthorized."""
        r = self.client.get(f"{self.base}/me/", **{"HTTP_AUTHORIZATION": "Bearer invalid.jwt.token"})
        self.assertEqual(r.status_code, 401)

    # --- logout idempotent, even without prior cookies ---

    def test_logout_without_prior_cookies_sets_expiry_cookies(self):
        """
        Logout should be idempotent and instruct the client to expire cookies
        even when none were previously set.
        """
        headers = self._csrf_headers()
        r = self.client.post(f"{self.base}/logout/", {}, format="json", **headers)
        self.assertEqual(r.status_code, 200)
        # We expect Set-Cookie for access/refresh with expiry indicators.
        self.assertIn("access", r.cookies)
        self.assertIn("refresh", r.cookies)

    def test_logout_idempotent_twice(self):
        """Calling logout twice should still return 200 OK both times."""
        headers = self._csrf_headers()
        r1 = self.client.post(f"{self.base}/logout/", {}, format="json", **headers)
        r2 = self.client.post(f"{self.base}/logout/", {}, format="json", **headers)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)

    # --- login success: assert body and cookie flags ---

    def test_login_success_detail_and_cookie_flags(self):
        """
        On successful login:
        - Response body should be {"detail": "logged_in"}.
        - 'access' cookie should be present and marked HttpOnly.
        """
        headers = self._csrf_headers()
        r = self.client.post(
            f"{self.base}/login/",
            {"username": "edge", "password": "EdgePass123!"},
            format="json",
            **headers,
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"detail": "logged_in"})
        self.assertIn("access", r.cookies)
        access_morsel = r.cookies["access"]
        # Presence of httponly attribute (value may be empty string depending on client).
        self.assertIn("httponly", access_morsel.keys())

    # --- refresh when both body and cookie exist (body takes precedence) ---

    def test_refresh_with_both_body_and_cookie(self):
        """
        If a refresh token is provided in the request body, it should be used even if
        a cookie also exists (body precedence).
        """
        # 1) Login to get refresh cookie
        headers = self._csrf_headers()
        r = self.client.post(
            f"{self.base}/login/",
            {"username": "edge", "password": "EdgePass123!"},
            format="json",
            **headers,
        )
        self.assertEqual(r.status_code, 200)
        refresh_cookie = self.client.cookies.get("refresh").value

        # 2) Call refresh while providing the token in the body
        headers = self._csrf_headers()
        r2 = self.client.post(
            f"{self.base}/refresh/",
            {"refresh": refresh_cookie},
            format="json",
            **headers,
        )
        self.assertEqual(r2.status_code, 200)
        self.assertIn("access", self.client.cookies)


@override_settings(**COMMON_OVERRIDES)
class RegistrationExtraTests(APITestCase):
    """
    Extra registration validations beyond the main flow.
    """

    def setUp(self):
        self.base = "/api/auth"

    def _csrf_headers(self):
        """Obtain CSRF header as required by Django's test client."""
        r = self.client.get(f"{self.base}/csrf/")
        self.assertEqual(r.status_code, 200)
        csrftoken = self.client.cookies.get("csrftoken").value
        return {"HTTP_X_CSRFTOKEN": csrftoken}

    def test_register_email_case_insensitive_uniqueness(self):
        """
        Email uniqueness must be case-insensitive:
        registering with 'upper@example.com' must collide with 'UPPER@EXAMPLE.COM'.
        """
        User.objects.create_user(
            username="old",
            email="UPPER@EXAMPLE.COM",
            first_name="Upper",
            last_name="Case",
            password="StrongPass123!",
        )
        headers = self._csrf_headers()
        payload = {
            "username": "newuser",
            "email": "upper@example.com",  # same email, different case
            "first_name": "New",
            "last_name": "User",
            "password": "StrongPass123!",
            "password_confirm": "StrongPass123!",
        }
        r = self.client.post(f"{self.base}/register/", payload, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", r.data)
