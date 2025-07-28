# app/user.py

class User:
    """
    Represents a user in the banking system.
    Stores email, hashed password, balance, transaction history, and confirmation status.
    """
    def __init__(self, username, email, password_hash, balance=0.0, confirmed=False):
        self.username = username
        self.email = email
        self.password = password_hash
        self.balance = balance
        self.history = []
        self.confirmed = confirmed

    def to_dict(self):
        """
        Converts the User object into a dictionary for JSON serialization.
        """
        return {
            "email": self.email,
            "password": self.password,
            "balance": self.balance,
            "history": self.history,
            "confirmed": self.confirmed
        }

    @staticmethod
    def from_dict(username, data):
        """
        Creates a User object from a dictionary (loaded from JSON).
        """
        user = User(
            username=username,
            email=data["email"],
            password_hash=data["password"],
            balance=data.get("balance", 0.0),
            confirmed=data.get("confirmed", False)
        )
        user.history = data.get("history", [])
        return user
