from django.urls import path
from admin_account.views import (
    RoleManagementView,
    PermissionManagementView,
    AdminOnlyView,
    AdminUserManagementView,
    UserRoleAssignmentView,
    SomeView,
    AdminLoginView,
    AdminUserLogView,
)

urlpatterns = [
    path("", AdminOnlyView.as_view(), name="admin"),
    path("login/", AdminLoginView.as_view(), name="admin-login"),
    path("users/", AdminUserManagementView.as_view(), name="admin-user-management"),
    path(
        "users/logs/<str:user_id>/",
        AdminUserLogView.as_view(),
        name="user-activity-logs",
    ),
    path(
        "users/<str:user_id>/",
        AdminUserManagementView.as_view(),
        name="admin-user-detail",
    ),
    path("roles/", RoleManagementView.as_view(), name="role-management"),
    path("roles/<str:role_id>/", RoleManagementView.as_view(), name="role-detail"),
    path(
        "permissions/",
        PermissionManagementView.as_view(),
        name="permission-management",
    ),
    path(
        "permissions/<str:permission_id>/",
        PermissionManagementView.as_view(),
        name="permission-detail",
    ),
    path(
        "users/<str:user_id>/role/",
        UserRoleAssignmentView.as_view(),
        name="assign-role",
    ),
    # ---------------------temp-------
    path("protected/", SomeView.as_view(), name="protected"),
]
