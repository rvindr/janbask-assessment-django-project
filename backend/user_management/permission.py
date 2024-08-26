from rest_framework.permissions import BasePermission
from user_management.mongo_client import roles_collection
import logging


class IsAdminPermission(BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and is an admin
        user = request.user
        return user.is_authenticated and user.is_admin


from rest_framework.permissions import BasePermission
from user_management.mongo_client import roles_collection


class HasReadPermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False

        role_id = user.role_id
        if not role_id:
            return False

        role = roles_collection.find_one({"_id": role_id})
        if not role:
            return False

        return "READ" in role.get("permissions", [])


class HasCreatePermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False

        role_id = user.role_id
        if not role_id:
            return False

        role = roles_collection.find_one({"_id": role_id})
        if not role:
            return False

        return "CREATE" in role.get("permissions", [])


class HasUpdatePermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False

        role_id = user.role_id
        if not role_id:
            return False

        role = roles_collection.find_one({"_id": role_id})
        if not role:
            return False

        return "UPDATE" in role.get("permissions", [])


class HasDeletePermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False

        role_id = user.role_id
        if not role_id:
            return False

        role = roles_collection.find_one({"_id": role_id})
        if not role:
            return False

        return "DELETE" in role.get("permissions", [])


from functools import wraps
from rest_framework.exceptions import PermissionDenied


def check_permission(permission):
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
            if not role or permission not in role.get("permissions", []):
                raise PermissionDenied(
                    f"You don't have permission to '{permission}', Permission is required!"
                )

            return func(self, request, *args, **kwargs)

        return wrapped

    return decorator
