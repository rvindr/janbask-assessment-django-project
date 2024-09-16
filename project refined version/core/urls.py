from django.urls import path
from core.customTokenRefreshView import CustomTokenRefreshView
from core.views import (
    RegistrationView,
    LoginView,
    LogoutView,
    UserChangePassword,
    SendPasswordResetEmailView,
    PasswordResetView,
    AdminUserManagementView,
    UserStatusView,
    RoleManagementView,
    PermissionManagementView,
    UserRoleAssignmentView,
    SampleView,
    UserActivityLogView
)

urlpatterns = [
    # User management
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', UserChangePassword.as_view(), name='change-password'),
    path('password-reset-email/', SendPasswordResetEmailView.as_view(),
         name='send-password-reset-email'),
    path('reset-password/<uid>/<token>/',
         PasswordResetView.as_view(), name='password-reset'),

    # Admin management
    path('admin/users/', AdminUserManagementView.as_view(), name='admin-users'),
    path('admin/users/<str:user_id>/',
         AdminUserManagementView.as_view(), name='admin-users'),
    path('admin/user-status/<str:user_id>/',
         UserStatusView.as_view(), name='user-status'),
    path('admin/roles/', RoleManagementView.as_view(), name='roles-management'),
    path('admin/roles/<str:role_id>/',
         RoleManagementView.as_view(), name='roles-management'),
    path('admin/permissions/', PermissionManagementView.as_view(),
         name='permissions-management'),
    path('admin/permissions/<str:permission_id>/',
         PermissionManagementView.as_view(), name='permissions-management'),
    path('admin/logs/', UserActivityLogView.as_view(), name='user-activity-logs'),


    # Role assignment
    path('admin/user/<str:user_id>/assign-role/',
         UserRoleAssignmentView.as_view(), name='assign-role'),
    path('admin/user/<str:user_id>/remove-role/<str:role_id>/',
         UserRoleAssignmentView.as_view(), name='remove-role'),

    path(
        "token/refresh/",
        CustomTokenRefreshView.as_view(),
        name="custom_token_refresh",
    ),

    # sample view
    path('admin/sample-view/', SampleView.as_view(), name='sample-view'),
]
