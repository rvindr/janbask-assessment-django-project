from django.urls import path, include
from admin_account.views import (
    AdminLoginView,
    AdminDashboard,
    AdminUserListView,
    AdminLogoutView,
    AdminRegisterUserView,
    AdminEditUserView,
    AdminUserDetail,
    AdminUserDeactivateView,
    AdminUserActivateView,
    AdminUserLogView,
    RolesView,
    PermissionsView,
    PermissionCreateView,
    CreateRoleView,
    AssignRoleView,
)

urlpatterns = [
    path("", AdminLoginView.as_view(), name="admin-login"),
    path("admin-logout/", AdminLogoutView.as_view(), name="admin-logout"),
    path("admin-dashboard/", AdminDashboard.as_view(), name="admin-dashboard"),
    path("admin-dashboard/users/", AdminUserListView.as_view(), name="admin-user-list"),
    path(
        "admin-user-register/",
        AdminRegisterUserView.as_view(),
        name="admin-user-register",
    ),
    path(
        "admin/users/edit/<str:user_id>/",
        AdminEditUserView.as_view(),
        name="admin-edit-user",
    ),
    path(
        "admin/user-detail/<str:user_id>/",
        AdminUserDetail.as_view(),
        name="admin-user-detail",
    ),
    path(
        "admin/user-deactivate/<str:user_id>/",
        AdminUserDeactivateView.as_view(),
        name="user-deactivate",
    ),
    path(
        "admin/user-activate/<str:user_id>/",
        AdminUserActivateView.as_view(),
        name="user-activate",
    ),
    path(
        "users/logs/<str:user_id>/",
        AdminUserLogView.as_view(),
        name="user-activity-logs-view",
    ),
    path("admin/permission/", PermissionsView.as_view(), name="permissions"),
    path(
        "create-permission/", PermissionCreateView.as_view(), name="create-permission"
    ),
    path("admin/roles/", RolesView.as_view(), name="roles"),
    path("create-role/", CreateRoleView.as_view(), name="create-role"),
    path("users/<str:user_id>/role/", AssignRoleView.as_view(), name="assign-role"),
]
