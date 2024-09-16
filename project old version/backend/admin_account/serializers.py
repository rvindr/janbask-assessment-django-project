from rest_framework import serializers
from user_management.mongo_client import (
    roles_collection,
    permissions_collection,
)
from user_management.mongo_client import users_collection
from account.models import UserModel
from rest_framework.exceptions import AuthenticationFailed
from admin_account.models import RoleModel, PermissionModel
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken


class AdminLoginSerializer(serializers.Serializer):
    """
    Serializer for admin login, handles authentication and token generation.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def get_user_from_mongodb(self, email: str) -> UserModel:
        """
        Retrieve user from MongoDB by email.
        """
        user_data = users_collection.find_one({"email": email})
        if user_data:
            user_data["_id"] = str(user_data.get("_id"))
            return UserModel(**user_data)
        raise ValueError("No user found")

    def validate(self, attrs):
        """
        Validate login credentials and generate tokens if successful.
        """
        email = attrs.get("email")
        password = attrs.get("password")

        if not email or not password:
            raise AuthenticationFailed("Email and password are required!")

        try:
            user = self.get_user_from_mongodb(email)
        except ValueError as e:
            raise AuthenticationFailed("No user found")

        if user.is_locked_out():
            raise AuthenticationFailed("Account is locked. Please try again later.")

        if not check_password(password, user.password):
            user.increment_failed_attempts()
            raise AuthenticationFailed("Incorrect password")

        if not user.is_active:
            raise AuthenticationFailed("User is inactive")

        if not user.is_admin:
            raise AuthenticationFailed("Admin access required")

        user.reset_failed_attempts()

        refresh_token = RefreshToken.for_user(user)
        access_token = refresh_token.access_token

        return {
            "refresh_token": str(refresh_token),
            "access_token": str(access_token),
            "user_id": str(user.id),
            "email": email,
        }


class PermissionSerializer(serializers.Serializer):
    """
    Serializer for permissions, handles creation and validation.
    """

    id = serializers.CharField(read_only=True, source="_id")
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255, required=False)

    def create(self, validated_data):
        """
        Create a new permission and store it in MongoDB.
        """
        validated_data["name"] = validated_data["name"].upper()
        validated_data["description"] = validated_data["description"].lower()
        permission = PermissionModel(**validated_data)
        res = permissions_collection.insert_one(permission.dict(by_alias=True))
        validated_data["_id"] = str(res.inserted_id)
        return validated_data


class RoleSerializer(serializers.Serializer):
    """
    Serializer for roles, handles creation and permission retrieval.
    """

    id = serializers.CharField(read_only=True, source="_id")
    name = serializers.CharField(max_length=255)
    permissions = serializers.SerializerMethodField()

    def get_permissions(self, role):
        """
        Retrieve permissions associated with the role.
        """
        permission_ids = role.get("permissions", [])
        permissions = permissions_collection.find({"_id": {"$in": permission_ids}})
        return [
            permission.get("name", "Unknown Permission") for permission in permissions
        ]

    def create(self, validated_data):
        """
        Create a new role and store it in MongoDB.
        """
        validated_data["name"] = validated_data["name"].title()
        role = RoleModel(**validated_data)
        res = roles_collection.insert_one(role.dict(by_alias=True))
        role_id = str(res.inserted_id)

        validated_data["_id"] = role_id

        permissions = validated_data.get("permissions", [])
        if permissions:
            valid_permissions = permissions_collection.find(
                {"_id": {"$in": permissions}}
            ).distinct("_id")
            roles_collection.update_one(
                {"_id": role_id}, {"$set": {"permissions": valid_permissions}}
            )

        return validated_data


class UserRoleAssignmentSerializer(serializers.Serializer):
    """
    Serializer for assigning roles to users, validates role ID.
    """

    role_id = serializers.CharField()

    def validate_role_id(self, role_id):
        """
        Validate the role ID exists in MongoDB.
        """
        if not roles_collection.find_one({"_id": role_id}):
            raise serializers.ValidationError("Role ID does not exist")
        return role_id
