from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from user_management.mongo_client import users_collection
from account.models import UserModel
from bson import ObjectId
from getpass import getpass


class Command(BaseCommand):
    help = "Create an admin user interactively"

    def handle(self, *args, **kwargs):
        # Prompt for user input
        email = input("Email: ")
        password = getpass("Password: ")
        first_name = input("First name: ")
        last_name = input("Last name: ")

        # Check if user already exists
        if users_collection.find_one({"email": email}):
            self.stdout.write(
                self.style.ERROR(f"User with email {email} already exists")
            )
            return

        # Hash the password using Django's make_password
        hashed_password = make_password(password)

        # Create the user object
        user = UserModel(
            id=str(ObjectId()),
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            is_active=True,
            is_admin=True,
        )

        # Insert the user into the MongoDB collection
        users_collection.insert_one(user.dict(by_alias=True))

        self.stdout.write(
            self.style.SUCCESS(f"Admin user created successfully with email {email}")
        )
