from django.shortcuts import render, redirect
from django.views import View
from django.contrib import messages
import requests
from django.conf import settings
import time
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


API_BASE_URL = settings.API_BASE_URL


class HomeView(View):
    def get(self, request):
        return render(request, "home.html")


class Registration(View):
    def get(self, request):
        return render(request, "register.html")

    def post(self, request):
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect("register")
        data = {
            "first_name": request.POST.get("first_name"),
            "last_name": request.POST.get("last_name"),
            "email": request.POST.get("email"),
            "password": password1,
        }
        url = f"{API_BASE_URL}/api/register/"

        response = requests.post(url, data=data)

        if response.status_code == 201:
            messages.success(request, "You have registered successfully!")
            return redirect("login")
        else:
            res = response.json()
            error = res.get("error", {})
            msg = res.get("error", "something went wrong, Registration failed!")

            return render(request, "register.html", {"message": msg})


class LoginView(View):
    def get(self, request):
        if "auth_token" in request.session:
            return redirect("home")  # change to user_dashboard

        return render(request, "login.html")

    def post(self, request):
        data = {
            "email": request.POST.get("email"),
            "password": request.POST.get("password"),
        }
        url = f"{API_BASE_URL}/api/login/"
        response = requests.post(url, data=data)

        if response.status_code == 200:

            data = response.json()
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")

            request.session["auth_token"] = access_token
            request.session["refresh_token"] = refresh_token

            return redirect("profile")
        else:
            data = response.json()
            return render(request, "login.html", {"message": data})


class UserProfile(View):
    def get(self, request):
        # Fetch user info from the backend API
        token = request.session.get("auth_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        response = requests.get(f"{API_BASE_URL}/api/user-info/", headers=headers)

        if response.status_code == 200:
            user_info = response.json().get("user_info")

            return render(request, "user_profile.html", {"user_info": user_info})
        else:
            return render(
                request,
                "user_profile.html",
                {"error": "Unable to fetch user information"},
            )


class LogoutView(View):

    def post(self, request):
        url = f"{API_BASE_URL}/api/logout/"
        token = request.session.get("auth_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            request.session.flush()
            return redirect("home")
        else:
            # Get the current URL to redirect back to the same page
            current_url = request.META.get("HTTP_REFERER", "home.html")
            # Render the current page with the error message
            return render(
                request, current_url, {"logout_error": "Error occurred during logout"}
            )


class ChangePasswordView(View):

    def get(self, request):
        return render(request, "change_password.html")

    def post(self, request):
        # Handle password change
        url = f"{API_BASE_URL}/api/change-password/"
        token = request.session.get("auth_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        data = {
            "old_password": request.POST.get("old_password"),
            "new_password": request.POST.get("new_password"),
        }
        response = requests.post(url, headers=headers, data=data)

        if response.status_code == 200:
            # Log out the user and redirect to login page
            request.session.flush()

            messages.success(
                request, response.json().get("detail", "Password changed successfully")
            )
            return redirect("login")
        else:
            # Show error message
            error_msg = response.json().get("error", "An error occurred")
            return render(request, "change_password.html", {"message": error_msg})


class SendResetPasswordLinkView(View):

    def post(self, request):
        data = {"email": request.POST.get("email")}
        url = f"{API_BASE_URL}/api/send-reset-password/"
        response = requests.post(url, data=data)

        if response.status_code == 200:

            data = response.json()
            messages.success(request, data)
            return redirect("login")
        else:
            data = response.json().get("detail")
            return render(request, "login.html", {"message": data})


class ResetPasswordView(View):

    def get(self, request, uid, token):
        context = {
            "uid": uid,
            "token": token,
        }
        return render(request, "reset_password.html", context)

    def post(self, request, uid, token):
        new_password = request.POST.get("new_password")
        data = {
            "new_password": new_password,
        }
        url = f"{API_BASE_URL}/api/reset-password/{uid}/{token}/"
        response = requests.post(url, json=data)

        if response.status_code == 200:
            msg = response.json().get("message", "Password reset successfully.")
            messages.success(request, msg)
            return redirect("login")
        else:
            try:
                error_data = response.json()
                error_message = error_data.get(
                    "message", "An error occurred. Please try again."
                )
            except Exception as e:
                error_message = response.text

            context = {"uid": uid, "token": token, "error_message": error_message}
            return render(request, "reset_password.html", context)
