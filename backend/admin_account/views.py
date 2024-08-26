from rest_framework.decorators import APIView
from rest_framework.response import Response
from rest_framework import status
from user_management.mongo_client import users_collection, logs_collection
from account.serializers import RegistrationSerializer
from admin_account.serializers import (
    RoleSerializer,
    PermissionSerializer,
    UserRoleAssignmentSerializer,
    AdminLoginSerializer,
)
from rest_framework.permissions import IsAuthenticated
from user_management.customJWTAuthentication import CustomJWTAuthentication
from user_management.permission import IsAdminPermission, check_permission
from user_management.mongo_client import roles_collection, permissions_collection
from account.serializers import UserSerializer
from account.models import UserModel
from account.utils import Util
from bson import json_util


class AdminLoginView(APIView):
    """
    Handles admin login and returns JWT tokens if credentials are valid.
    """

    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(
            {"error": serializer.errors}, status=status.HTTP_401_UNAUTHORIZED
        )


class AdminOnlyView(APIView):
    """
    View accessible only to authenticated admin users.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        return Response({"message": "Admin access granted"})


class AdminUserManagementView(APIView):
    """
    Manages users: retrieve, create, update, activate, and deactivate.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request, user_id=None):
        if user_id:
            user = users_collection.find_one({"_id": user_id})
            if user:
                user_data = UserSerializer(user).data
                return Response({"user": user_data})
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        users = users_collection.find()
        user_list = [UserSerializer(user).data for user in users]
        return Response({"users": user_list})

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.save()
            email_data = {
                "subject": "Your account was registered successfully!",
                "body": f"""Dear {data["first_name"]} {data["last_name"]},
                
                Your account has been created successfully. Your registered email is {data["email"]}.
                
                Note: Please use the 'Forgot Password' link on the login page to reset your password.""",
                "to_email": data["email"],
            }
            Util.send_email(email_data)
            return Response(
                {"detail": "User registered successfully!", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def put(self, request, user_id):
        user_data = request.data
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = UserSerializer(data=user_data, partial=True)
        if serializer.is_valid():
            updated_data = serializer.validated_data
            updated_user = users_collection.find_one_and_update(
                {"_id": user_id}, {"$set": user_data}, return_document=True
            )
            if not updated_user:
                return Response(
                    {"error": "Failed to update user"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user_model = UserModel(**updated_user)
            user_model.log_activity(
                action="User Updated", details={"updated_fields": user_data}
            )
            return Response({"message": "User updated successfully"})
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def patch(self, request, user_id):
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        users_collection.update_one({"_id": user_id}, {"$set": {"is_active": True}})
        return Response(
            {"message": "User activated successfully"}, status=status.HTTP_200_OK
        )

    def delete(self, request, user_id):
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        users_collection.update_one({"_id": user_id}, {"$set": {"is_active": False}})
        return Response(
            {"message": "User deactivated successfully"}, status=status.HTTP_200_OK
        )


class AdminUserLogView(APIView):
    """
    Retrieves and returns logs for a specific user.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request, user_id):
        user_logs = list(logs_collection.find({"user_id": user_id}))
        if not user_logs:
            return Response(
                {"error": "No logs found for this user"},
                status=status.HTTP_404_NOT_FOUND,
            )
        logs_json = json_util.dumps(user_logs)
        return Response({"user_logs": logs_json}, status=status.HTTP_200_OK)


class RoleManagementView(APIView):
    """
    Manages roles: retrieve, create, and delete.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        roles = roles_collection.find()
        role_list = [RoleSerializer(role).data for role in roles]
        return Response({"roles": role_list}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            role_data = serializer.save()
            return Response(
                {"detail": "Role created successfully", "data": role_data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, role_id):
        role = roles_collection.find_one({"_id": role_id})
        if not role:
            return Response(
                {"error": "Role not found"}, status=status.HTTP_404_NOT_FOUND
            )
        roles_collection.delete_one({"_id": role_id})
        return Response(
            {"detail": "Role deleted successfully"}, status=status.HTTP_200_OK
        )


class PermissionManagementView(APIView):
    """
    Manages permissions: retrieve, create, and delete.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        permissions = permissions_collection.find()
        permission_list = [
            PermissionSerializer(permission).data for permission in permissions
        ]
        return Response({"permissions": permission_list}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "Permission created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, permission_id):
        permission = permissions_collection.find_one({"_id": permission_id})
        if not permission:
            return Response(
                {"error": "Permission not found"}, status=status.HTTP_404_NOT_FOUND
            )
        roles_collection.update_many(
            {"permissions": permission_id}, {"$pull": {"permissions": permission_id}}
        )
        permissions_collection.delete_one({"_id": permission_id})
        return Response(
            {"detail": "Permission deleted successfully"}, status=status.HTTP_200_OK
        )


class UserRoleAssignmentView(APIView):
    """
    Assigns a role to a user.
    """

    def put(self, request, user_id):
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = UserRoleAssignmentSerializer(data=request.data)
        if serializer.is_valid():
            role_id = serializer.validated_data["role_id"]
            role = roles_collection.find_one({"_id": role_id})
            is_admin = role.get("name").lower() == "admin"
            if is_admin:
                users_collection.update_one(
                    {"_id": user_id},
                    {"$set": {"role_id": role_id, "is_admin": is_admin}},
                )
            users_collection.update_one(
                {"_id": user_id}, {"$set": {"role_id": role_id}}
            )
            return Response({"message": "Role assigned to user successfully"})
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class SomeView(APIView):
    """
    Example view with various permissions (READ, WRITE, UPDATE, DELETE).
    """

    permission_classes = [IsAuthenticated]

    @check_permission("READ")
    def get(self, request):
        return Response({"message": "GET access granted"})

    @check_permission("WRITE")
    def post(self, request):
        return Response({"message": "POST access granted"})

    @check_permission("UPDATE")
    def put(self, request):
        return Response({"message": "PUT access granted"})

    @check_permission("UPDATE")
    def patch(self, request):
        return Response({"message": "PATCH access granted"})

    @check_permission("DELETE")
    def delete(self, request):
        return Response({"message": "DELETE access granted"})
