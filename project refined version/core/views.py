from rest_framework.decorators import APIView
from rest_framework.response import Response
from rest_framework import status
from user_management.mongo_client import (
    users_collection, roles_collection, permissions_collection, logs_collection)
from core.serializer import (
    UserSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    PasswordResetEmailSerializer,
    PasswordResetSerializer,
    RoleSerializer,
    PermissionSerializer,
    UserRoleAssignmentSerializer,
    UserActivitySerializer
)
from rest_framework.permissions import IsAuthenticated, AllowAny
from core.customJWTAuthentication import CustomJWTAuthentication
from core.utils import Util
from core.permissions import IsAdminPermission,UserPermission
from core.models import UserModel
from rest_framework import serializers


class RegistrationView(APIView):
    """
    Handle user registration.
    """

    def post(self, request):
        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "user registered successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class LoginView(APIView):
    """
    Handle user login and return authentication tokens.
    """

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)

        return Response(
            {"error": serializer.errors}, status=status.HTTP_401_UNAUTHORIZED
        )


class LogoutView(APIView):
    """
    Handle user logout by invalidating JWT tokens.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout_class = CustomJWTAuthentication()
        logout_res = logout_class.logout(request)

        return Response(logout_res, status=status.HTTP_200_OK)


class UserChangePassword(APIView):
    """
    Allow authenticated users to change their password.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = ChangePasswordSerializer(
            data=request.data, context={"user": user})

        if serializer.is_valid():
            # Save the new password
            serializer.save()
            # Invalidate the user's JWT token to force logout
            logout_class = CustomJWTAuthentication()
            logout_res = logout_class.logout(request)

            return Response(
                {"detail": "Password changed successfully"}, status=status.HTTP_200_OK
            )

        return Response(
            {"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class SendPasswordResetEmailView(APIView):
    """
    Handle sending password reset emails.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetEmailSerializer(data=request.data)

        if serializer.is_valid():
            return Response(
                {"detail": "Password reset link sent. Please check your email"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetView(APIView):
    """
    Handle password reset using a token and UID.
    """

    permission_classes = [AllowAny]

    def post(self, request, uid, token):
        serializer = PasswordResetSerializer(
            data=request.data, context={"uid": uid, "token": token}
        )

        if serializer.is_valid():
            response_data = serializer.save()

            return Response(response_data, status=status.HTTP_200_OK)

        return Response(
            {"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


# admin views
class AdminUserManagementView(APIView):
    """
    Manages users: retrieve, create, update, activate, and deactivate.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        users = users_collection.find()
        user_list = list(users)
        serializer = UserSerializer(user_list, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.save()
            return Response(
                {"detail": "User registered successfully!", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def patch(self, request, user_id):
        user_data = request.data
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        serializer = UserSerializer(data=user_data, partial=True)
        if serializer.is_valid():
            updated_user = serializer.update(
                instance=user, validated_data=user_data)
            return Response(updated_user, status=status.HTTP_200_OK)

        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )


class UserStatusView(APIView):

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def patch(self, request, user_id):
        # Activate a user
        user_serializer = UserSerializer()

        try:
            response_data = user_serializer.activate_user(user_id)
            return Response(response_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id):
        # Activate a user
        user_serializer = UserSerializer()

        try:
            response_data = user_serializer.deactivate_user(user_id)
            return Response(response_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)


class RoleManagementView(APIView):
    """
    Manages roles: retrieve, create, and delete.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        """
        Retrieve all roles and return serialized data.
        """
        roles = roles_collection.find()
        serializer = RoleSerializer(roles, many=True)
        return Response({"roles": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Create a new role.
        """
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
        serializer = RoleSerializer()
        try:
            response_data = serializer.delete(role_id)
            return Response(response_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)


class PermissionManagementView(APIView):
    """
    Manages permissions: retrieve, create, and delete.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        # Retrieve all permissions and return serialized data.
        permissions = permissions_collection.find()
        serializer = PermissionSerializer(permissions, many=True)
        return Response({"permissions": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        # Create a new permission and return serialized data.
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            permission_data = serializer.save()
            return Response(
                {"detail": "Permission created successfully", "data": permission_data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, permission_id):
        # Delete a permission and return the result of the deletion.

        serializer = PermissionSerializer()
        try:
            response_data = serializer.delete_permission(permission_id)
            return Response(response_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)


class UserRoleAssignmentView(APIView):
    """
    Assigns or removes a role to/from a user.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminPermission]

    def put(self, request, user_id):
        """
        Assign a role to a user.
        """
        serializer = UserRoleAssignmentSerializer(data=request.data)
        if serializer.is_valid():
            try:
                response_data = serializer.assign_role_to_user(user_id)
                return Response(response_data, status=status.HTTP_200_OK)
            except serializers.ValidationError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, user_id, role_id):
        """
        Remove a role from a user.
        """
        serializer = UserRoleAssignmentSerializer(data={"role_id": role_id})
        if serializer.is_valid():
            try:
                response_data = serializer.remove_role_from_user(
                    user_id, role_id)
                return Response(response_data, status=status.HTTP_200_OK)
            except serializers.ValidationError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class UserActivityLogView(APIView):
    """
    Retrieve logs of user activities filtered by email.
    """

    permission_classes = [IsAuthenticated, IsAdminPermission]

    def get(self, request):
        email = request.query_params.get('email')

        if email:
            # Retrieve logs filtered by email
            logs = logs_collection.find({"email": email})
        else:
            logs = logs_collection.find()

        log_list = list(logs)
        serializer = UserActivitySerializer(log_list, many=True)

        return Response({"logs": serializer.data}, status=status.HTTP_200_OK)



class SampleView(APIView):
    permission_classes = [IsAuthenticated, UserPermission('CREATE')]


    def get(self, request):
        return Response({"message": "You have access to this view because you have the necessary permission."})
