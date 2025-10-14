from django.urls import path, re_path
from . import views

urlpatterns = [
    path("login/", views.CookieTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("refresh/", views.CookieTokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", views.logout_view, name="logout"),
    path("me/", views.me_view, name="me"),
    path("csrf/", views.csrf_view, name="csrf"),
    path("health/", views.health_view, name="health"),
    re_path(r"^register/?$", views.register_view, name="register"),
]
