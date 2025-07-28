# app/bank.py

import json
import os
from datetime import datetime
from app.user import User


class Bank:
    """
    Manages user registration, login, deposit, and withdraw operations.
    Handles saving/loading users from users.json.
    """

    def __init__(self, file_path="users.json"):
        self.file_path = file_path
        self.users = self.load_users()

    def load_users(self):
        """
        Loads all users from the JSON file and returns a dictionary of User objects.
        """
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                try:
                    data = json.load(f)
                    return {username: User.from_dict(username, udata) for username, udata in data.items()}
                except json.JSONDecodeError:
                    return {}
        return {}

    def save_users(self):
        """
        Saves all users to the JSON file in dictionary form.
        """
        with open(self.file_path, "w") as f:
            json.dump({u: user.to_dict() for u, user in self.users.items()}, f, indent=4)

    def get_user(self, username):
        return self.users.get(username)

    def register_user(self, user: User):
        """
        Registers a new user and saves them to storage.
        """
        self.users[user.username] = user
        self.save_users()

    def authenticate(self, username, password_plaintext, bcrypt_module):
        """
        Checks if username exists and password is valid using bcrypt.
        """
        user = self.get_user(username)
        if user and bcrypt_module.checkpw(password_plaintext.encode(), user.password.encode()):
            return user
        return None

    def deposit(self, username, amount):
        """
        Adds balance and appends transaction history with timestamp.
        """
        user = self.get_user(username)
        if user:
            user.balance += amount
            now = datetime.now().strftime("%d %b %Y at %I:%M %p")
            user.history.append(f"Deposited ${amount:.2f} on {now}")
            self.save_users()
            return True
        return False


    def withdraw(self, username, amount):
        """
        Deducts balance if enough funds exist and appends timestamped history.
        """
        user = self.get_user(username)
        if user and user.balance >= amount:
            user.balance -= amount
            now = datetime.now().strftime("%d %b %Y at %I:%M %p")
            user.history.append(f"Withdrew ${amount:.2f} on {now}")
            self.save_users()
            return True
        return False

