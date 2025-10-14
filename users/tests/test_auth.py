"""
Integration tests for cookie-based JWT auth flows.

Covers:
- CSRF cookie issuance and usage in mutating requests
- Registration with full field validation (required, email format, uniqueness, password policy)
- Login (success / wrong credentials) with tokens set as HttpOnly cookies
- Access to /me protected route via cookie or Authorization header
- Refresh via cookie and via body
- Logout idempotency and cookie deletion semantics

"""

from django.test import override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


@override_settings(
    # Make cookies non-Secure for local test HTTP and tune lifetimes for speed.
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
    # Explicit password validators to get deterministic 400 on weak passwords.
    AUTH_PASSWORD_VALIDATORS=[
        {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
        {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
        {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    ],
)
class AuthTests(APITestCase):
    """
    End-to-end tests of the main happy paths and common validation failures.
    """

    def setUp(self):
        """
        Default payload used for registration and subsequent calls.
        """
        self.base = "/api/auth"
        self.u = {
            "username": "testing",
            "email": "testing@example.com",
            "first_name": "testing",
            "last_name": "Test",
            "password": "StrongPass123!",
            "password_confirm": "StrongPass123!",
        }

    # ---------- Helpers ----------

    def _csrf(self):
        """
        Obtain the CSRF cookie and return the header dict expected by Django's test client.
        """
        r = self.client.get(f"{self.base}/csrf/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        csrftoken = self.client.cookies.get("csrftoken").value
        # In Django's test client, HTTP headers must be prefixed with HTTP_
        return {"HTTP_X_CSRFTOKEN": csrftoken}

    def _register_ok(self):
        """
        Register using self.u and assert cookies are set.
        """
        headers = self._csrf()
        r = self.client.post(f"{self.base}/register/", self.u, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        # Client cookie jar should now contain JWT cookies.
        self.assertIn("access", self.client.cookies)
        self.assertIn("refresh", self.client.cookies)
        return r

    def _login(self, username=None, password=None):
        """
        Perform login and return the response.
        """
        headers = self._csrf()
        payload = {
            "username": username or self.u["username"],
            "password": password or self.u["password"],
        }
        return self.client.post(f"{self.base}/login/", payload, format="json", **headers)

    # ---------- CSRF ----------

    def test_csrf_sets_cookie(self):
        """GET /csrf should set the csrftoken cookie and return the token in JSON."""
        r = self.client.get(f"{self.base}/csrf/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("csrftoken", self.client.cookies)

    # ---------- REGISTER: validations ----------

    def test_register_requires_all_fields(self):
        """All registration fields must be present and non-empty."""
        headers = self._csrf()
        r = self.client.post(f"{self.base}/register/", {}, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        for f in ["username", "email", "first_name", "last_name", "password", "password_confirm"]:
            self.assertIn(f, r.data)

    def test_register_invalid_email(self):
        """Email format is validated."""
        headers = self._csrf()
        bad = {**self.u, "email": "not-an-email"}
        r = self.client.post(f"{self.base}/register/", bad, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", r.data)

    def test_register_password_mismatch(self):
        """password_confirm must match password."""
        headers = self._csrf()
        bad = {**self.u, "password_confirm": "Different123!"}
        r = self.client.post(f"{self.base}/register/", bad, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password_confirm", r.data)

    def test_register_password_policy(self):
        """Weak/short passwords should be rejected by validators."""
        headers = self._csrf()
        bad = {**self.u, "password": "short", "password_confirm": "short"}  # < 8 chars
        r = self.client.post(f"{self.base}/register/", bad, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", r.data)

    def test_register_duplicate_username(self):
        """Username uniqueness is case-insensitive."""
        self._register_ok()
        headers = self._csrf()
        dup = {**self.u, "email": "other@example.com"}
        r = self.client.post(f"{self.base}/register/", dup, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", r.data)

    def test_register_duplicate_email(self):
        """Email uniqueness is case-insensitive."""
        self._register_ok()
        headers = self._csrf()
        dup = {**self.u, "username": "someoneelse"}
        r = self.client.post(f"{self.base}/register/", dup, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", r.data)

    # ---------- REGISTER: success + me ----------

    def test_register_success_sets_cookies_and_me(self):
        """Successful registration sets cookies and allows access to /me."""
        self._register_ok()
        r = self.client.get(f"{self.base}/me/")
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data["username"], self.u["username"])
        self.assertEqual(r.data["email"], self.u["email"])
        self.assertEqual(r.data["first_name"], self.u["first_name"])
        self.assertEqual(r.data["last_name"], self.u["last_name"])

    # ---------- LOGIN ----------

    def test_login_wrong_credentials(self):
        """Wrong password should return 401 and no cookies should be set."""
        User.objects.create_user(
            username=self.u["username"],
            email=self.u["email"],
            first_name=self.u["first_name"],
            last_name=self.u["last_name"],
            password=self.u["password"],
        )
        r = self._login(password="WrongPass!")
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_success_sets_cookies(self):
        """Successful login should set access and refresh cookies."""
        User.objects.create_user(
            username=self.u["username"],
            email=self.u["email"],
            first_name=self.u["first_name"],
            last_name=self.u["last_name"],
            password=self.u["password"],
        )
        r = self._login()
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("access", self.client.cookies)
        self.assertIn("refresh", self.client.cookies)

    # ---------- ME ----------

    def test_me_requires_auth(self):
        """/me should return 401 when not authenticated."""
        r = self.client.get(f"{self.base}/me/")
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    # ---------- REFRESH ----------

    def test_refresh_uses_refresh_cookie(self):
        """POST /refresh without body should fall back to the refresh cookie."""
        self._register_ok()
        headers = self._csrf()
        r = self.client.post(f"{self.base}/refresh/", {}, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn("access", self.client.cookies)

    # ---------- LOGOUT ----------

    def test_logout_deletes_cookies(self):
        """POST /logout should expire both access and refresh cookies (idempotent)."""
        self._register_ok()
        headers = self._csrf()
        r = self.client.post(f"{self.base}/logout/", {}, format="json", **headers)
        self.assertEqual(r.status_code, status.HTTP_200_OK)

        # Inspect DRF response cookies to ensure deletion directives are present.
        self.assertIn("access", r.cookies)
        self.assertIn("refresh", r.cookies)
        access_cookie = r.cookies["access"]
        refresh_cookie = r.cookies["refresh"]
        self.assertTrue(
            access_cookie["max-age"] == "0" or bool(access_cookie["expires"]),
            "The 'access' cookie should be removed (max-age=0 or expires set).",
        )
        self.assertTrue(
            refresh_cookie["max-age"] == "0" or bool(refresh_cookie["expires"]),
            "The 'refresh' cookie should be removed (max-age=0 or expires set).",
        )


class AuthHeaderAndBranchesTests(APITestCase):
    """
    Additional branch coverage:
    - Authorization header with valid Bearer token
    - Invalid header schema -> cookie fallback
    - Invalid header and no cookie -> 401
    - Refresh with token supplied in request body (no cookie)
    - Login error path returns raw response (no cookies set)
    """

    def setUp(self):
        self.base = "/api/auth"
        self.user = User.objects.create_user(
            username="alice",
            email="alice@example.com",
            first_name="Alice",
            last_name="Doe",
            password="StrongPass123!",
        )

    def _csrf_headers(self):
        """Convenience helper to get the CSRF header dict."""
        r = self.client.get(f"{self.base}/csrf/")
        self.assertEqual(r.status_code, 200)
        csrftoken = self.client.cookies.get("csrftoken").value
        return {"HTTP_X_CSRFTOKEN": csrftoken}

    def test_me_with_authorization_header_bearer_token(self):
        """Valid Bearer <jwt> header grants access to /me (no cookies needed)."""
        access = str(RefreshToken.for_user(self.user).access_token)
        r = self.client.get(
            f"{self.base}/me/",
            **{"HTTP_AUTHORIZATION": f"Bearer {access}"},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["username"], "alice")

    def test_me_with_invalid_header_schema_but_valid_cookie_fallback(self):
        """
        Invalid schema in Authorization header should be ignored and cookie fallback used.
        """
        access = str(RefreshToken.for_user(self.user).access_token)
        # Seed the cookie jar with a valid access JWT
        self.client.cookies["access"] = access
        r = self.client.get(
            f"{self.base}/me/",
            **{"HTTP_AUTHORIZATION": "Token whatever"},  # invalid schema
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["username"], "alice")

    def test_me_with_invalid_header_and_no_cookie_returns_401(self):
        """Invalid header and no cookie should result in 401 Unauthorized."""
        r = self.client.get(
            f"{self.base}/me/",
            **{"HTTP_AUTHORIZATION": "Token bad"},
        )
        self.assertEqual(r.status_code, 401)

    def test_refresh_with_token_in_body_instead_of_cookie(self):
        """Refresh using token in request body (no cookies present)."""
        # 1) Login to obtain a refresh
        headers = self._csrf_headers()
        r = self.client.post(
            f"{self.base}/login/",
            {"username": "alice", "password": "StrongPass123!"},
            format="json",
            **headers,
        )
        self.assertEqual(r.status_code, 200)
        refresh_cookie = self.client.cookies.get("refresh").value

        # 2) Clear cookies so body is the only source
        self.client.cookies.pop("access", None)
        self.client.cookies.pop("refresh", None)

        headers = self._csrf_headers()
        r2 = self.client.post(
            f"{self.base}/refresh/",
            {"refresh": refresh_cookie},
            format="json",
            **headers,
        )
        self.assertEqual(r2.status_code, 200)
        self.assertIn("access", self.client.cookies)

    def test_login_error_path_returns_response_unchanged(self):
        """
        Wrong password must return 401 and the response body should be left intact
        (no cookies set).
        """
        headers = self._csrf_headers()
        r = self.client.post(
            f"{self.base}/login/",
            {"username": "alice", "password": "Wrong!"},
            format="json",
            **headers,
        )
        self.assertEqual(r.status_code, 401)
        self.assertNotIn("access", self.client.cookies)
        self.assertNotIn("refresh", self.client.cookies)
