from rest_framework.permissions import BasePermission
from user_management.mongo_client import roles_collection, permissions_collection
from functools import wraps
from rest_framework.exceptions import PermissionDenied
from user_management.mongo_client import users_collection, roles_collection


class IsAdminPermission(BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and is an admin
        user = request.user
        return user.is_authenticated and user.is_admin


def get_permission_id(permission_name):
    """Fetch permission ID by permission name."""
    permission = permissions_collection.find_one({"name": permission_name})
    return permission["_id"] if permission else None


def check_permission(permission_name):
    def decorator(func):
        @wraps(func)
        def wrapped(self, request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                raise PermissionDenied("User is not authenticated")

            role_id = user.role_id
            if not role_id:
                raise PermissionDenied("User does not have a role assigned")

            role = roles_collection.find_one({"_id": role_id})
            if not role:
                raise PermissionDenied("Role not found")

            permission_id = get_permission_id(permission_name)
            if not permission_id or permission_id not in role.get("permissions", []):
                raise PermissionDenied(
                    f"You don't have permission to '{permission_name}', Permission is required!"
                )

            return func(self, request, *args, **kwargs)

        return wrapped

    return decorator
 

class HasPermission(BasePermission):
    def __init__(self, permission_name=None):
        self.permission_name = permission_name

    def has_permission(self, request, view):
        user = request.user

        # Check if user is authenticated
        if not user.is_authenticated:
            raise PermissionDenied("User is not authenticated")

        # Retrieve user's role and check if they have the required permission
        role_id = user.role_id
        if not role_id:
            raise PermissionDenied("User does not have a role assigned")

        role = roles_collection.find_one({"_id": role_id})
        if not role:
            raise PermissionDenied("Role not found")

        permission_id = get_permission_id(self.permission_name)
        if not permission_id or permission_id not in role.get("permissions", []):
            raise PermissionDenied(
                f"You don't have permission to '{self.permission_name}', Permission is required!"
            )

        return True

class UserPermission:
    def __init__(self, permission_name):
        self.permission_name = permission_name

    def __call__(self):
        return HasPermission(self.permission_name)
    












# class HasPermission(BasePermission):
#     def __init__(self, permission_name=None):
#         self.permission_name = permission_name

#     def has_permission(self, request, view):
#         user = request.user

#         # Check if user is authenticated
#         if not user.is_authenticated:
#             raise PermissionDenied("User is not authenticated")

#         # Retrieve user's role and check if they have the required permission
#         role_id = user.role_id
#         if not role_id:
#             raise PermissionDenied("User does not have a role assigned")

#         role = roles_collection.find_one({"_id": role_id})
#         if not role:
#             raise PermissionDenied("Role not found")

#         permission_id = get_permission_id(self.permission_name)
#         if not permission_id or permission_id not in role.get("permissions", []):
#             raise PermissionDenied(
#                 f"You don't have permission to '{self.permission_name}', Permission is required!"
#             )

#         return True

#     @classmethod
#     def UserPermission(cls, permission_name):
#         return cls(permission_name)
   