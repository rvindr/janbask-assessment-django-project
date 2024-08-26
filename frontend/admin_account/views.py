from django.shortcuts import render, redirect
from django.views import View
from django.contrib import messages
import requests
from django.conf import settings
import time
from bson import ObjectId
from datetime import datetime
import json

API_BASE_URL = settings.API_BASE_URL


class AdminLoginView(View):
    def get(self, request):
        # Redirect if already logged in
        if "auth_token" in request.session:
            return redirect("admin-dashboard")  # Redirect to admin dashboard

        return render(request, "admin_login.html")

    def post(self, request):
        # Prepare data for API request
        data = {
            "email": request.POST.get("email"),
            "password": request.POST.get("password"),
        }

        # Call the backend API for login
        url = f"{API_BASE_URL}/api/admin/login/"
        response = requests.post(url, data=data)

        # Check the API response
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")

            # Store tokens in session
            request.session["auth_token"] = access_token
            request.session["refresh_token"] = refresh_token

            # Redirect to admin dashboard
            return redirect("admin-dashboard")
        else:
            # Display error message if login fails
            # error_message = response.json().get('error', 'Invalid credentials')
            return render(request, "admin_login.html", {"message": response.text})


class AdminLogoutView(View):

    def post(self, request):
        url = f"{API_BASE_URL}/api/logout/"
        token = request.session.get("auth_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            request.session.flush()
            return redirect("admin-login")
        else:
            request.session.flush()
            return redirect("admin-login")


class AdminDashboard(View):
    def get(self, request):

        return render(request, "admin_dashboard.html")


class AdminUserListView(View):
    template_name = "admin_user_list.html"

    def get(self, request):
        # Get the JWT token from the session
        auth_token = request.session.get("auth_token")

        # Define the API URL
        api_url = f"{API_BASE_URL}/api/admin/users/"

        # Make a GET request to the backend API to retrieve user data
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            users = response.json().get("users", [])
        else:
            users = []
            # Handle the error accordingly
            print(f"Error fetching users: {response.status_code}")

        # Pass the user data to the template
        context = {"users": users}
        return render(request, self.template_name, context)


class AdminRegisterUserView(View):
    def get(self, request):
        return render(request, "admin_user_register.html")

    def post(self, request):
        auth_token = request.session.get("auth_token")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect("admin-user-register")

        data = {
            "first_name": request.POST.get("first_name"),
            "last_name": request.POST.get("last_name"),
            "email": request.POST.get("email"),
            "password": password1,
        }

        api_url = f"{API_BASE_URL}/api/admin/users/"
        headers = {"Authorization": f"Bearer {auth_token}"}

        response = requests.post(api_url, headers=headers, json=data)

        if response.status_code == 201:
            messages.success(
                request, response.json().get("detail", "User registered successfully!")
            )
            return redirect("admin-user-register")
        else:
            error_msg = (
                response.json()
                .get("errors", {})
                .get("non_field_errors", ["Registration failed!"])[0]
            )
            return render(request, "admin_user_register.html", {"message": error_msg})


class AdminEditUserView(View):
    def get(self, request, user_id):
        auth_token = request.session.get("auth_token")
        api_url = f"{API_BASE_URL}/api/admin/users/{user_id}/"
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Fetch user data from API
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            user = response.json().get("user", {})

            return render(request, "admin_user_edit.html", {"user": user})
        else:
            return render(
                request, "admin_user_edit.html", {"message": "User not found."}
            )

    def post(self, request, user_id):

        auth_token = request.session.get("auth_token")
        api_url = f"{API_BASE_URL}/api/admin/users/{user_id}/"
        headers = {"Authorization": f"Bearer {auth_token}"}

        user_data = {
            "first_name": request.POST.get("first_name"),
            "last_name": request.POST.get("last_name"),
            "email": request.POST.get("email"),
            "password": request.POST.get("password"),  # Assuming password is optional
        }

        response = requests.put(api_url, headers=headers, data=user_data)

        if response.status_code == 200:
            messages.success(request, "User updated successfully!")
            return redirect(
                "admin-user-list"
            )  # Redirect to a list of users or an appropriate page
        else:
            error_msg = response.json().get("error", "Update failed.")
            return render(
                request,
                "admin_user_edit.html",
                {"user": user_data, "message": error_msg},
            )


class AdminUserDetail(View):

    def get(self, request, user_id):
        # Get the JWT token from the session
        auth_token = request.session.get("auth_token")

        # Define the API URL
        api_url = f"{API_BASE_URL}/api/admin/users/{user_id}/"

        # Make a GET request to the backend API to retrieve user data
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            users = response.json().get("user", [])
        else:
            users = []
            # Handle the error accordingly
            print(f"Error fetching users: {response.status_code}")

        # Pass the user data to the template
        context = {"user": users}
        return render(request, "admin_user_detail.html", context)


class AdminUserDeactivateView(View):
    def get(self, request, user_id):

        auth_token = request.session.get("auth_token")

        # Define the API URL
        api_url = f"{API_BASE_URL}/api/admin/users/{user_id}/"

        # Make a GET request to the backend API to retrieve user data
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.delete(api_url, headers=headers)

        if response.status_code == 200:
            messages.success(request, "User deactivated successfully")
            return redirect("admin-user-list")
        else:
            error = response.json().get("error", "Something went wrong")
            return redirect("admin-user-list")


class AdminUserActivateView(View):
    def get(self, request, user_id):

        auth_token = request.session.get("auth_token")

        # Define the API URL
        api_url = f"{API_BASE_URL}/api/admin/users/{user_id}/"

        # Make a GET request to the backend API to retrieve user data
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.patch(api_url, headers=headers)

        if response.status_code == 200:
            messages.success(request, "User activated successfully")
            return redirect("admin-user-list")
        else:
            error = response.json().get("error", "Something went wrong")
            return redirect("admin-user-list")


class AdminUserLogView(View):
    def get(self, request, user_id):
        api_url = f"{API_BASE_URL}/api/admin/users/logs/{user_id}/"
        headers = {"Authorization": f"Bearer {request.session.get('auth_token')}"}
        response = requests.get(api_url, headers=headers)

        logs = []
        if response.status_code == 200:
            user_logs = response.json().get("user_logs", "[]")

            try:
                parsed_logs = json.loads(
                    user_logs
                )  # Convert JSON string to Python objects
                for log in parsed_logs:
                    timestamp = log.get("timestamp", {}).get("$date", None)
                    if isinstance(timestamp, (int, float)):
                        timestamp_seconds = timestamp / 1000
                        log["timestamp"] = datetime.utcfromtimestamp(
                            timestamp_seconds
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        log["timestamp"] = "Unknown timestamp format"

                    # Extract details and format them
                    details = log.get("details", {})
                    formatted_details = []
                    for key, value in details.items():
                        if isinstance(value, dict):
                            value = ", ".join(f"{k}: {v}" for k, v in value.items())
                        formatted_details.append(f"{key}: {value}")
                    log["details"] = "<br>".join(
                        formatted_details
                    )  # Use <br> for line breaks in HTML

                    logs.append(log)
            except json.JSONDecodeError as e:
                print(f"JSON decoding error: {e}")
                logs.append(
                    {
                        "timestamp": "Error decoding logs",
                        "action": "",
                        "details": "Error decoding details",
                    }
                )

        return render(request, "admin_user_logs.html", {"logs": logs})


class PermissionsView(View):

    def get(self, request):
        auth_token = request.session.get("auth_token")

        # Define the API URL
        api_url = f"{API_BASE_URL}/api/admin/permissions/"

        # Make a GET request to the backend API to retrieve user data
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            permission_data = response.json().get("permissions", [])

            return render(request, "permissions.html", {"permissions": permission_data})
        else:
            messages.error(request, "Something went wrong")
            return redirect("admin-dashboard")

    def post(self, request):
        permission_id = request.POST.get("permission_id")
        auth_token = request.session.get("auth_token")

        if not permission_id:
            messages.error(request, "Permission ID is required")
            return redirect("permissions")

        # Define the API URL for deleting a permission
        api_url = f"{API_BASE_URL}/api/admin/permissions/{permission_id}/"

        # Make a DELETE request to the backend API to delete the permission
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.delete(api_url, headers=headers)

        if response.status_code == 200:
            msg = response.json().get("detail", "Permission deleted successfully")
            messages.success(request, msg)
        else:
            messages.error(request, "Failed to delete permission")

        return redirect("permissions")


class PermissionCreateView(View):
    def get(self, request):
        # Display the permission creation form
        return render(request, "create_permission.html")

    def post(self, request):
        # Get the JWT token from the session
        auth_token = request.session.get("auth_token")

        # Prepare data for API request
        data = {
            "name": request.POST.get("name"),
            "description": request.POST.get("description"),
        }

        # Define the API URL for creating a new permission
        api_url = f"{API_BASE_URL}/api/admin/permissions/"
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Make a POST request to the backend API to create the permission
        response = requests.post(api_url, headers=headers, data=data)

        # Check the API response
        if response.status_code == 201:
            # If the permission is created successfully, display a success message
            messages.success(request, "Permission created successfully!")
            return redirect("permissions")  # Redirect to the permissions list view
        else:
            # If the creation fails, display an error message
            error_msg = response.json().get("error", "Failed to create permission")
            return render(request, "create_permission.html", {"message": error_msg})


class RolesView(View):

    def get(self, request):
        auth_token = request.session.get("auth_token")

        # Define the API URL
        api_url = f"{API_BASE_URL}/api/admin/roles/"

        # Make a GET request to the backend API to retrieve user data
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            role_data = response.json().get("roles", [])

            return render(request, "roles_list.html", {"roles": role_data})
        else:
            messages.error(request, "Something went wrong")
            return redirect("admin-dashboard")

    def post(self, request):
        role_id = request.POST.get("role_id")
        auth_token = request.session.get("auth_token")

        if not role_id:
            messages.error(request, "Role ID is required")
            return redirect("roles")

        # Define the API URL for deleting a permission
        api_url = f"{API_BASE_URL}/api/admin/roles/{role_id}/"

        # Make a DELETE request to the backend API to delete the permission
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.delete(api_url, headers=headers)

        if response.status_code == 200:
            msg = response.json().get("detail", "Role deleted successfully!")
            messages.success(request, msg)
        else:
            messages.error(request, "Failed to delete role")

        return redirect("roles")


class CreateRoleView(View):
    def get(self, request):
        # Fetch permissions from the backend API
        auth_token = request.session.get("auth_token")
        api_url = f"{API_BASE_URL}/api/admin/permissions/"
        headers = {"Authorization": f"Bearer {auth_token}"}

        response = requests.get(api_url, headers=headers)
        permissions = []

        if response.status_code == 200:
            permissions = response.json().get("permissions", [])
        else:
            messages.error(request, "Failed to fetch permissions.")

        return render(request, "create_role.html", {"permissions": permissions})

    def post(self, request):
        role_name = request.POST.get("name")
        permissions = request.POST.getlist("permissions")

        # Prepare data for API request
        data = {"name": role_name, "permissions": permissions}

        # Call the backend API to create a role
        auth_token = request.session.get("auth_token")
        api_url = f"{API_BASE_URL}/api/admin/roles/"
        headers = {"Authorization": f"Bearer {auth_token}"}

        response = requests.post(api_url, headers=headers, json=data)

        # Check the API response
        if response.status_code == 201:
            messages.success(request, "Role created successfully!")
            return redirect(
                "roles"
            )  # Redirect to roles list or another appropriate page
        else:
            error_message = response.json().get("errors", "Failed to create role")
            messages.error(request, error_message)
            return render(request, "create_role.html", {"errors": error_message})


class AssignRoleView(View):
    def get(self, request, user_id):
        auth_token = request.session.get("auth_token")

        # Fetch existing roles from the backend API
        api_url = f"{API_BASE_URL}/api/admin/roles/"
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(api_url, headers=headers)

        roles = []
        if response.status_code == 200:
            roles = response.json().get("roles", [])
        else:
            messages.error(request, "Failed to fetch roles.")

        return render(request, "assign_role.html", {"roles": roles, "user_id": user_id})

    def post(self, request, user_id):
        auth_token = request.session.get("auth_token")
        role_id = request.POST.get("role_id")

        if not role_id:
            messages.error(request, "Role ID is required.")
            return redirect("assign-role", user_id=user_id)

        # Assign role via backend API
        api_url = f"{API_BASE_URL}/api/admin/users/{user_id}/role/"
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.put(api_url, data={"role_id": role_id}, headers=headers)

        if response.status_code == 200:
            messages.success(request, "Role assigned successfully.")
        else:
            messages.error(request, "Failed to assign role.")

        return redirect("assign-role", user_id=user_id)
