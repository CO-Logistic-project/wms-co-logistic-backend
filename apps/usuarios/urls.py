from django.urls import path

from .views import (
    CurrentUserView,
    LoginView,
    LogoutView,
    PasswordChangeView,
    RefreshView,
    UserPasswordResetView,
    PermissionListView,
    RoleDetailView,
    RoleListCreateView,
    UserDetailView,
    UserListCreateView,
    UserRoleAssignmentView,
    UserStatusView,
)


urlpatterns = [
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/refresh/", RefreshView.as_view(), name="auth-refresh"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path(
        "auth/password/change/",
        PasswordChangeView.as_view(),
        name="auth-password-change",
    ),
    path("auth/me/", CurrentUserView.as_view(), name="auth-current-user"),
    path("users/", UserListCreateView.as_view(), name="user-list-create"),
    path("users/<uuid:user_id>/", UserDetailView.as_view(), name="user-detail"),
    path(
        "users/<uuid:user_id>/roles/",
        UserRoleAssignmentView.as_view(),
        name="user-role-assignment",
    ),
    path(
        "users/<uuid:user_id>/status/",
        UserStatusView.as_view(),
        name="user-status",
    ),
    path(
        "users/<uuid:user_id>/password/reset/",
        UserPasswordResetView.as_view(),
        name="user-password-reset",
    ),
    path("roles/", RoleListCreateView.as_view(), name="role-list-create"),
    path("roles/<int:role_id>/", RoleDetailView.as_view(), name="role-detail"),
    path("permissions/", PermissionListView.as_view(), name="permission-list"),
]
