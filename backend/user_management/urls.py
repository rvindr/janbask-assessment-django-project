from django.contrib import admin
from django.urls import path, include
from user_management.customTokenRefreshView import CustomTokenRefreshView

urlpatterns = [
    path("api/", include("account.urls")),
    path("api/admin/", include("admin_account.urls")),
    path(
        "api/token/refresh/",
        CustomTokenRefreshView.as_view(),
        name="custom_token_refresh",
    ),
]
