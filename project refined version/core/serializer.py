from django.conf import settings
from datetime import timedelta, datetime
from rest_framework import serializers
from user_management.mongo_client import (
    users_collection,
    token_collection,
    roles_collection,
)
from django.contrib.auth.hashers import make_password, check_password
from core.models import UserModel, PermissionModel, RoleModel, UserActivity
from rest_framework.exceptions import AuthenticationFailed
from bson import ObjectId
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError
import jwt
from core.utils import Util
from django.utils.encoding import smart_str, force_bytes
from django.utils.http import urlsafe_base64_encode
from user_management.mongo_client import permissions_collection, logs_collection


def log_user_activity(email, action, details=None):
    activity = UserActivity(
        email=email,
        action=action,
        details=details or {},
    )
    logs_collection.insert_one(activity.dict())


class UserSerializer(serializers.Serializer):
    """
    Handles user registration validation and creation.
    """

    first_name = serializers.CharField(max_length=255)
    last_name = serializers.CharField(max_length=255)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    role_id = serializers.CharField(required=False)

    def validate_email(self, data):
        """
        Check if email already exists.
        """
        if users_collection.find_one({"email": data}):
            raise serializers.ValidationError("Email already exists")
        return data

    def validate_role_id(self, role_id):
        """
        Validate role ID.
        """
        if role_id and not roles_collection.find_one({"_id": ObjectId(role_id)}):
            raise serializers.ValidationError("Invalid role ID")
        return role_id

    def create(self, validated_data):
        """
        Create a new user.
        """
        validated_data["password"] = make_password(validated_data["password"])
        role_id = validated_data.pop("role_id", None)
        if role_id:
            validated_data["role_id"] = role_id
        user = UserModel(**validated_data)
        res = users_collection.insert_one(user.dict(by_alias=True))
        email_data = {
            "subject": "Your account was registered successfully!",
            "body": f"""Dear {validated_data["first_name"]} {validated_data["last_name"]},
                
                Your account has been created successfully. Your registered email is {validated_data["email"]}.
                
                Note: Please use the 'Forgot Password' link on the login page to reset your password.""",
            "to_email": validated_data["email"],
        }
        Util.send_email(email_data)
        validated_data["_id"] = str(res.inserted_id)
        log_user_activity(
            email=validated_data['email'],
            action='user created'
        )
        return validated_data

    def update(self, instance, validated_data):
        # Update only the fields provided in validated_data
        if "password" in validated_data:
            validated_data["password"] = make_password(
                validated_data["password"])

        if "role_id" in validated_data:
            role_id = validated_data["role_id"]
            role = roles_collection.find_one({"_id": role_id})
            if not role:
                raise serializers.ValidationError("Invalid role ID")
            validated_data["role_id"] = role_id

        instance.update(validated_data)
        users_collection.update_one({"_id": instance["_id"]}, {
                                    "$set": validated_data})
        return validated_data

    def deactivate_user(self, user_id):
        # Deactivate a user by setting `is_active` to False.
        user = users_collection.find_one({"_id": user_id})
        if not user:
            raise serializers.ValidationError("User not found")
        users_collection.update_one(
            {"_id": user_id}, {"$set": {"is_active": False}})

        log_user_activity(
            email=user['email'],
            action='user deactivated'
        )

        return {"message": "User deactivated successfully"}

    def activate_user(self, user_id):
        # Activate a user by setting `is_active` to True.
        user = users_collection.find_one({"_id": user_id})
        if not user:
            raise serializers.ValidationError("User not found")
        users_collection.update_one(
            {"_id": user_id}, {"$set": {"is_active": True}})
        log_user_activity(
            email=user['email'],
            action='user activated'
        )
        return {"message": "User activated successfully"}


class LoginSerializer(serializers.Serializer):
    """
    Handles user login validation and token generation.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def get_user_from_mongodb(self, email: str) -> UserModel:
        """
        Retrieve user by email.
        """
        user_data = users_collection.find_one({"email": email})
        if user_data:
            return UserModel(**user_data)
        raise ValueError("No user found")

    def validate(self, attrs):
        """
        Validate login credentials and generate tokens.
        """
        email = attrs.get("email")
        password = attrs.get("password")
        if not email or not password:
            raise AuthenticationFailed("Email and password are required!")
        try:
            user = self.get_user_from_mongodb(email)
        except ValueError:
            raise AuthenticationFailed("No user found")

        if not check_password(password, user.password):
            raise AuthenticationFailed("Incorrect password")

        if not user.is_active:
            raise AuthenticationFailed("User is inactive")

        log_user_activity(
            email=email,
            action='user logged in'
        )

        refresh_token = RefreshToken.for_user(user)
        access_token = refresh_token.access_token
        return {
            "refresh_token": str(refresh_token),
            "access_token": str(access_token),
            "user_id": str(user.id),
            "email": email,
        }


class ChangePasswordSerializer(serializers.Serializer):
    """
    Handles password change validation and updating.
    """

    old_password = serializers.CharField(write_only=True, min_length=8)
    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate_old_password(self, value):
        """
        Validate the old password.
        """
        user = self.context.get("user")
        if not check_password(value, user.password):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate(self, attrs):
        """
        Ensure new password is different from old password.
        """
        new_password = attrs.get("new_password")
        old_password = attrs.get("old_password")
        if old_password == new_password:
            raise serializers.ValidationError(
                "New password cannot be the same as the old password."
            )
        return attrs

    def save(self, **kwargs):
        """
        Save the new password.
        """
        user = self.context.get("user")
        new_password = self.validated_data["new_password"]
        hashed_password = make_password(new_password)
        users_collection.update_one(
            {"_id": user.id}, {"$set": {"password": hashed_password}}
        )

        return user


class PasswordResetEmailSerializer(serializers.Serializer):
    """
    Sends a password reset email.
    """

    email = serializers.EmailField()

    def validate(self, attrs):
        """
        Validate email and send reset email.
        """
        email = attrs.get("email")
        user_data = users_collection.find_one({"email": email})
        if not user_data:
            raise ValidationError("No user found with this email address")
        user_id = str(user_data["_id"])
        encoded_uid = urlsafe_base64_encode(force_bytes(user_id))
        payload = {"user_id": user_id, "exp": datetime.utcnow() +
                   timedelta(minutes=10)}
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        token_collection.insert_one(
            {
                "user_id": user_id,
                "token": token,
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(hours=10),
            }
        )
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{encoded_uid}/{token}/"
        # temp
        print(reset_url)
        # temp
        data = {
            "subject": "Reset Your Password",
            "body": f"Click following Link to reset your password \n {reset_url}",
            "to_email": user_data["email"],
        }
        Util.send_email(data)

        log_user_activity(
            email=user_data['email'],
            action='user reset password email sent'
        )
        return {"detail": "Password reset email has been sent."}


class PasswordResetSerializer(serializers.Serializer):
    """
    Resets a user's password.
    """

    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        """
        Validate reset token and UID.
        """
        new_password = attrs.get("new_password")
        token = self.context.get("token")
        uid = self.context.get("uid")
        try:
            decoded_token = jwt.decode(
                token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")
            token_exp = decoded_token.get("exp")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        if uid != urlsafe_base64_encode(force_bytes(user_id)):
            raise ValidationError("Invalid UID or Token")

        # Check if the token is expired
        if datetime.utcnow() > datetime.fromtimestamp(token_exp):
            raise AuthenticationFailed("Token has expired")

        user_data = users_collection.find_one({"_id": user_id})
        if not user_data:
            raise ValidationError("User not found")
        if not user_data["is_active"]:
            raise ValidationError("User is inactive")
        attrs["user"] = user_data
        attrs["token"] = token

        return attrs

    def save(self, **kwargs):
        """
        Save the new password.
        """
        new_password = self.validated_data["new_password"]
        user = self.validated_data["user"]
        user_id = user["_id"]
        token = self.validated_data["token"]
        hashed_password = make_password(new_password)
        users_collection.update_one(
            {"_id": user_id}, {"$set": {"password": hashed_password}}
        )

        token_collection.delete_one({"token": token})

        log_user_activity(
            email=user['email'],
            action='user password reset'
        )

        return {"detail": "Password has been reset successfully."}


# admin serializers

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

    def delete_permission(self, permission_id):

        permission = permissions_collection.find_one({"_id": permission_id})
        if not permission:
            raise serializers.ValidationError("Permission not found")
        roles_collection.update_many(
            {"permissions": permission_id}, {
                "$pull": {"permissions": permission_id}}
        )
        permissions_collection.delete_one({"_id": permission_id})
        return {"detail": "Permission deleted successfully"}


class RoleSerializer(serializers.Serializer):
    """
    Serializer for roles, handles creation, update, and permission retrieval.
    """
    id = serializers.CharField(read_only=True, source="_id")
    name = serializers.CharField(max_length=255)
    permissions = serializers.ListField(
        child=serializers.CharField(), required=True)

    def create(self, validated_data):
        """
        Create a new role and store it in MongoDB.
        """
        validated_data["name"] = validated_data["name"].title()
        role_id = str(ObjectId())
        validated_data["_id"] = role_id

        # Validate permissions
        permissions = validated_data.get("permissions", [])
        if permissions:
            valid_permissions = list(permissions_collection.find(
                {"_id": {"$in": permissions}}).distinct("_id"))
            if set(permissions) != set(valid_permissions):
                invalid_permissions = set(permissions) - set(valid_permissions)
                raise serializers.ValidationError(
                    f"Invalid permissions: {', '.join(invalid_permissions)}")

            validated_data["permissions"] = valid_permissions

        role = RoleModel(**validated_data)
        res = roles_collection.insert_one(role.dict(by_alias=True))
        validated_data["_id"] = str(res.inserted_id)

        return validated_data

    def delete(self, role_id):
        """
        Delete an existing role.
        """
        role = roles_collection.find_one({"_id": role_id})
        if not role:
            raise serializers.ValidationError("Role not found")
        roles_collection.delete_one({"_id": role_id})
        return {"detail": "Role deleted successfully"}

    def to_representation(self, instance):
        """
        Convert the role instance to a dictionary of primitive data types.
        """
        data = super().to_representation(instance)
        return data


class UserRoleAssignmentSerializer(serializers.Serializer):
    """
    Serializer for assigning and removing roles from users, validates role ID.
    """

    role_id = serializers.CharField()

    def validate_role_id(self, role_id):
        # Validate the role ID exists in MongoDB.
        if not roles_collection.find_one({"_id": role_id}):
            raise serializers.ValidationError("Role ID does not exist")
        return role_id

    def assign_role_to_user(self, user_id):
        # Assign a role to a user and set 'is_admin' flag if role is admin.

        role_id = self.validated_data.get("role_id")
        user = users_collection.find_one({"_id": user_id})
        if not user:
            raise serializers.ValidationError("User not found")

        role = roles_collection.find_one({"_id": role_id})
        if not role:
            raise serializers.ValidationError("Role not found")

        is_admin = role.get("name", "").lower() == "admin"
        users_collection.update_one(
            {"_id": user_id},
            {"$set": {"role_id": role_id, "is_admin": is_admin}}
        )
        return {"message": "Role assigned to user successfully"}

    def remove_role_from_user(self, user_id, role_id):
        # Remove a role from a user.
        user = users_collection.find_one({"_id": user_id})
        if not user:
            raise serializers.ValidationError("User not found")

        if role_id != user.get("role_id"):
            raise serializers.ValidationError(
                "Role is not assigned to this user")

        users_collection.update_one(
            {"_id": user_id},
            {"$set": {"role_id": None}}
        )
        return {"detail": "Role removed successfully from the user."}


class UserActivitySerializer(serializers.Serializer):
    id = serializers.CharField(source="_id", read_only=True)
    email = serializers.CharField()
    action = serializers.CharField()
    timestamp = serializers.DateTimeField()
    details = serializers.JSONField()
