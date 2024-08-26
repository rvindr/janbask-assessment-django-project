# Django Admin Portal

This is a Django-based administrative portal for managing user accounts, roles, permissions, and activity logs. The portal provides authentication and user management features, along with the ability to manage roles and permissions through a clean and organized interface.

## Features

- **Admin Authentication:** Admins can log in and out securely using JWT tokens.
- **User Management:** View, register, edit, activate/deactivate, and delete user accounts.
- **Role Management:** Create, edit, and assign roles to users.
- **Permission Management:** Define and assign permissions to roles.
- **User Activity Logs:** View detailed logs of user activities.
- **Dashboard:** Admin dashboard with an overview of the system.

## Installation

### Prerequisites

- Python 3.6+
- Django 3.0+
- `requests` package

### Setup

1. **Clone the repository:**
    ```bash
    git clone https://github.com/rvindr/janbask-assessment-django-project
    cd frontend
    ```

2. **Install dependencies:**
    It's recommended to use a virtual environment:
    ```bash
    python3 -m venv env
    source env/bin/activate

    # On Windows use `env\Scripts\activate`
    pip install -r requirements.txt
    ```

3. **Set up environment variables:**
    Create a `.env` file in the root directory of your project and add the following:
    ```env
    SECRET_KEY='secret key'
    ```

4. **Apply migrations:**
    ```bash
    python manage.py migrate
    ```

5. **Run the development server:**
    ```bash
    python manage.py runserver
    ```

6. **Access the application:**
    - For **admin login**, go to `http://127.0.0.1:8000/admin/`.
    - For **user login**, go to `http://127.0.0.1:8000/`.

## Project Structure

- **admin_account/views.py:** Contains the views for handling admin actions like login, user management, role and permission management, etc.
- **admin_account/urls.py:** URL routing for all admin-related pages.

## Usage

### Admin Login

1. Navigate to the admin login page at `/admin/`.
2. Enter your admin credentials.
3. Upon successful login, you will be redirected to the admin dashboard.

### User Login

1. Navigate to the user login page at `/`.
2. Enter your user credentials.
3. Upon successful login, you will be redirected to the user dashboard.

### Managing Users

- To view the list of users, go to `/admin-dashboard/users/`.
- Register a new user via `/admin-user-register/`.
- Edit an existing user via `/admin/users/edit/<user_id>/`.
- View detailed information about a user via `/admin/user-detail/<user_id>/`.
- Activate or deactivate users as needed.

### Managing Roles and Permissions

- View all roles via `/admin/roles/`.
- Create a new role via `/create-role/`.
- Assign a role to a user via `/users/<user_id>/role/`.
- View and manage permissions via `/admin/permission/`.
- Create a new permission via `/create-permission/`.

## Contributing

If you wish to contribute to this project, please create an issue or submit a pull request on the GitHub repository.



