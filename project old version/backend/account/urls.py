from django.urls import path
from account.views import (
    RegistrationView,
    LoginView,
    LogoutView,
    UserChangePassword,
    SendPasswordResetEmailView,
    PasswordResetView,
    UserInfoView,
)

urlpatterns = [
    path("register/", RegistrationView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("change-password/", UserChangePassword.as_view(), name="change-password"),
    path(
        "send-reset-password/",
        SendPasswordResetEmailView.as_view(),
        name="send-reset-password",
    ),
    path(
        "reset-password/<uid>/<token>/",
        PasswordResetView.as_view(),
        name="reset-password",
    ),
    path("user-info/", UserInfoView.as_view(), name="user-info"),
]
