from rest_framework.decorators import APIView
from rest_framework.response import Response
from rest_framework import status
from user_management.mongo_client import users_collection
from account.serializers import (
    RegistrationSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    PasswordResetEmailSerializer,
    PasswordResetSerializer,
)
from rest_framework.permissions import IsAuthenticated, AllowAny
from user_management.customJWTAuthentication import CustomJWTAuthentication
from account.serializers import UserSerializer  # UserCreateSerializer


class RegistrationView(APIView):
    """
    Handle user registration.
    """

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)

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
        serializer = ChangePasswordSerializer(data=request.data, context={"user": user})

        if serializer.is_valid():
            # Save the new password
            serializer.save()

            # Log the activity
            user.log_activity(
                action="Password Changed",
                details={"reason": "User changed their password."},
            )
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


class UserInfoView(APIView):
    """
    Retrieve information about the authenticated user.
    """

    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the authenticated user's ID from the request
        user_id = request.user.id

        # Fetch the user information from MongoDB
        user = users_collection.find_one({"_id": user_id})
        if not user:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # Serialize the user data
        serializer = UserSerializer(user)
        return Response({"user_info": serializer.data}, status=status.HTTP_200_OK)
