from django.conf import settings
from datetime import timedelta, datetime
from rest_framework import serializers
from user_management.mongo_client import (
    users_collection,
    token_collection,
    roles_collection,
)
from django.contrib.auth.hashers import make_password, check_password
from account.models import UserModel
from rest_framework.exceptions import AuthenticationFailed
from bson import ObjectId
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError
import jwt
from account.utils import Util
from django.utils.encoding import smart_str, force_bytes
from django.utils.http import urlsafe_base64_encode
from user_management.mongo_client import permissions_collection


class RegistrationSerializer(serializers.Serializer):
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
        validated_data["_id"] = str(res.inserted_id)
        return validated_data


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
            user_data["_id"] = str(user_data.get("_id"))
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
        if user.is_locked_out():
            raise AuthenticationFailed("Account is locked. Please try again later.")
        if not check_password(password, user.password):
            user.increment_failed_attempts()
            raise AuthenticationFailed("Incorrect password")
        if not user.is_active:
            raise AuthenticationFailed("User is inactive")
        user.reset_failed_attempts()
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
        payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(minutes=10)}
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        token_collection.insert_one(
            {
                "user_id": user_id,
                "token": token,
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(hours=1),
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
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        if uid != urlsafe_base64_encode(force_bytes(user_id)):
            raise ValidationError("Invalid UID or Token")
        user_data = users_collection.find_one({"_id": user_id})
        if not user_data:
            raise ValidationError("User not found")
        if not user_data["is_active"]:
            raise ValidationError("User is inactive")
        attrs["user"] = user_data
        return attrs

    def save(self, **kwargs):
        """
        Save the new password.
        """
        new_password = self.validated_data["new_password"]
        user = self.validated_data["user"]
        user_id = user["_id"]
        hashed_password = make_password(new_password)
        users_collection.update_one(
            {"_id": user_id}, {"$set": {"password": hashed_password}}
        )
        return {"detail": "Password has been reset successfully."}


class UserSerializer(serializers.Serializer):
    """
    Serializes user data.
    """

    id = serializers.CharField(read_only=True, source="_id")
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=255)
    last_name = serializers.CharField(max_length=255)
    is_active = serializers.BooleanField()
    is_admin = serializers.BooleanField()
    password = serializers.CharField(write_only=True, required=False)
    role_id = serializers.CharField(read_only=True, required=False)
    permissions = serializers.SerializerMethodField()
    role_name = serializers.SerializerMethodField()

    def get_role_name(self, user):
        """
        Get the role name.
        """
        role_id = user.get("role_id")
        if role_id:
            role = roles_collection.find_one({"_id": role_id})
            if role:
                return role.get("name", "Unknown Role")
        return "No Role Assigned"

    def get_permissions(self, user):
        """
        Get permissions for the role.
        """
        role_id = user.get("role_id")
        if not role_id:
            return []
        role = roles_collection.find_one({"_id": role_id})
        if not role or "permissions" not in role:
            return []
        permission_ids = role["permissions"]
        permissions = permissions_collection.find({"_id": {"$in": permission_ids}})
        return [
            permission.get("name", "Unknown Permission") for permission in permissions
        ]

    def update(self, instance, validated_data):
        """
        Update user data.
        """
        update_data = {
            key: value for key, value in validated_data.items() if key != "password"
        }
        if "password" in validated_data:
            update_data["password"] = make_password(validated_data["password"])
        return validated_data
