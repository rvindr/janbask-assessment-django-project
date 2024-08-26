from django.urls import path, include
from user.views import (
    HomeView,
    Registration,
    LoginView,
    UserProfile,
    LogoutView,
    ChangePasswordView,
    SendResetPasswordLinkView,
    ResetPasswordView,
)

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("register/", Registration.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("reset-password/", SendResetPasswordLinkView.as_view(), name="reset-password"),
    path(
        "reset-password/<uid>/<token>/",
        ResetPasswordView.as_view(),
        name="reset-password",
    ),
    path("profile/", UserProfile.as_view(), name="profile"),
]
