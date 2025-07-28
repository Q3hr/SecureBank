from flask import Blueprint, render_template, request, redirect, flash, session, url_for
import bcrypt
import re
from datetime import datetime
import json
import os
import secrets
from flask_mail import Message
from app.init0 import mail
from itsdangerous import URLSafeTimedSerializer
from app.bank import Bank
bank = Bank()
from app.user import User


main = Blueprint('main', __name__)

# Load user data from JSON
def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

# Save user data to JSON
def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# Secure token generator
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer("secret-token-key")
    return serializer.dumps(email, salt="email-confirm-salt")

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer("secret-token-key")
    try:
        return serializer.loads(token, salt="email-confirm-salt", max_age=expiration)
    except:
        return False
# Token reset
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer("secret-token-key")
    return serializer.dumps(email, salt="reset-password-salt")

def confirm_reset_token(token, expiration=1800):  # 30 mins
    serializer = URLSafeTimedSerializer("secret-token-key")
    try:
        return serializer.loads(token, salt="reset-password-salt", max_age=expiration)
    except:
        return False

@main.route("/")
def home():
    if "username" in session:
        return redirect("/dashboard")
    return render_template("home.html")

@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        if (len(username) < 3 or username.isdigit() or not re.match(r"^[a-zA-Z0-9_.-]+$", username)):
            flash("Invalid username format.")
            return redirect("/register")

        if bank.get_user(username):
            flash("Username already exists.")
            return redirect("/register")

        for u in bank.users.values():
            if u.email == email:
                flash("Email is already registered.")
                return redirect("/register")

        if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            flash("Invalid email format.")
            return redirect("/register")

        if (len(password) < 8 or len(password) > 16 or not re.search(r'[A-Z]', password)
            or not re.search(r'[a-z]', password) or not re.search(r'\d', password)
            or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
            flash("Password does not meet strength requirements.")
            return redirect("/register")

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        new_user = User(username, email, hashed_pw)
        bank.register_user(new_user)

        token = generate_confirmation_token(email)
        confirm_url = url_for('main.confirm_email', token=token, _external=True)

        msg = Message('Confirm your SecureBank account', sender='tcpsender55@gmail.com', recipients=[email])
        msg.body = "This is a confirmation email for your SecureBank account."

        msg.html = f"""
    <html>
    <head>
        <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Cantarell, 'Open Sans', 'Helvetica Neue', Helvetica, Arial, sans-serif;
            background-color: #f8f9fa;
            padding: 20px;
        }}
        .email-container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            max-width: 500px;
            margin: auto;
        }}
        .btn {{
            display: inline-block;
            padding: 10px 20px;
            background-color: #fd6219;
            color: #ffffff !important;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
        }}
        </style>
    </head>
    <body>
        <div class="email-container">
        <h2>Confirm your SecureBank Account</h2>
        <p>Hello <strong>{username}</strong>,</p>
        <p>Thanks for registering with SecureBank. Please confirm your email address to activate your account.</p>
        <a href="{confirm_url}" class="btn">Confirm Account</a>
        <p style="margin-top: 30px; font-size: small; color: #888;">If you did not request this, you can ignore this email.</p>
        </div>
    </body>
    </html>
    """
        mail.send(msg)
        flash("Confirmation email sent. Please check your inbox.")
        return redirect("/login")

    return render_template("register.html")

@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = bank.get_user(username)
        if user and not user.confirmed:
            flash("Please confirm your email first.")
            return redirect("/login")

        if bank.authenticate(username, password, bcrypt):
            session.permanent = True  # ✅ activates timeout timer
            session["username"] = username
            flash(f"Welcome {username}!")
            return redirect("/dashboard")
        else:
            flash("Invalid credentials.")
            return redirect("/login")

    return render_template("login.html")

@main.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("Confirmation link expired or invalid.")
        return redirect("/")

    # Find username by email in bank.users
    username = None
    for u, udata in bank.users.items():
        if udata.email == email:
            username = u
            break

    if username:
        bank.users[username].confirmed = True
        bank.save_users()  # update JSON
        flash("Email confirmed. You can now login.")
    else:
        flash("User not found.")

    return redirect("/login")

@main.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('main.login'))
    user = bank.get_user(session['username'])
    return render_template("dashboard.html",
                          username=session["username"],
                          email=user.email,
                          balance=user.balance,
                          history=user.history,
                          bank=bank) 

@main.route("/logout")
def logout():
    session.pop("username", None)
    flash("You have been logged out.")
    return redirect("/")

@main.route("/deposit", methods=["POST"])
def deposit():
    if "username" not in session:
        flash("Your session has expired due to inactivity. Please log in again.")
        return redirect("/login")

    try:
        amount = float(request.form["amount"])
        if amount <= 0:
            raise ValueError
    except:
        flash("Invalid amount.")
        return redirect("/dashboard")

    if bank.deposit(session["username"], amount):
        flash(f"Deposited ${amount:.2f} successfully.")
    else:
        flash("Something went wrong.")

    return redirect("/dashboard")

@main.route("/withdraw", methods=["POST"])
def withdraw():
    if "username" not in session:
        flash("⚠️ Session expired. Please login first.")
        return redirect("/login")

    username = session["username"]
    amount_str = request.form["amount"]
    confirm_pw = request.form.get("confirm_password", "")

    try:
        amount = float(amount_str)
        if amount <= 0:
            raise ValueError
    except:
        flash("Invalid amount.")
        return redirect("/dashboard")

    user = bank.get_user(username)

    # 🔐 Only check password if amount ≥ 10000
    if amount >= 10000:
        if not bcrypt.checkpw(confirm_pw.encode(), user.password.encode()):
            flash("❌ Password incorrect.")
            return redirect("/dashboard")

        # Generate OTP and store in session
        otp = secrets.randbelow(900000) + 100000
        session["otp_code"] = str(otp)
        session["otp_amount"] = amount
        session["otp_time"] = datetime.now().timestamp()

        # Send OTP via email
        msg = Message("🔐 OTP Verification for Withdrawal",
                      sender="your_email@gmail.com",
                      recipients=[user.email])
        msg.body = f"Use this OTP to confirm your withdrawal: {otp}\n\nThis code is valid for 5 minutes."
        mail.send(msg)

        flash("✅ OTP sent to your email. Please verify to complete the transaction.")
        return redirect("/verify-otp")

    # 💸 For amount < 10000 → directly withdraw (no password check)
    if bank.withdraw(username, amount):
        flash(f"Withdrew ${amount:.2f} successfully.")
    else:
        flash("Insufficient balance.")

    return redirect("/dashboard")

@main.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "username" not in session:
        flash("Please login first.")
        return redirect("/login")

    if request.method == "POST":
        entered_otp = request.form["otp"]
        stored_otp = session.get("otp_code")
        otp_amount = session.get("otp_amount")
        otp_time = session.get("otp_time")

        if not stored_otp or not otp_amount or not otp_time:
            flash("Session expired or invalid.")
            return redirect("/dashboard")

        if datetime.now().timestamp() - otp_time > 300:
            flash("OTP expired. Try again.")
            return redirect("/dashboard")

        if entered_otp != stored_otp:
            flash("Incorrect OTP.")
            return redirect("/verify-otp")

        if bank.withdraw(session["username"], otp_amount):
            flash(f"✅ Withdrawn ${otp_amount:.2f} successfully via OTP.")
        else:
            flash("Insufficient balance.")

        # Clear OTP session
        session.pop("otp_code", None)
        session.pop("otp_amount", None)
        session.pop("otp_time", None)

        return redirect("/dashboard")

    return render_template("verify_otp.html")

@main.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        users = load_users()

        # Find user by email
        username = None
        for u, udata in users.items():
            if udata.get("email") == email:
                username = u
                break

        if username:
            token = generate_reset_token(email)
            reset_url = url_for("main.reset_with_token", token=token, _external=True)

            msg = Message("🔐 Reset Your SecureBank Password", recipients=[email], sender="your_email@gmail.com")
            msg.body = f"Click the link to reset your password: {reset_url}"
            msg.html = f"""
            <h3>Reset Your SecureBank Password</h3>
            <p>Hi <strong>{username}</strong>,</p>
            <p>We received a request to reset your password. Click the button below:</p>
            <a href="{reset_url}" style="display:inline-block;padding:10px 15px;background-color:#007bff;color:white;text-decoration:none;border-radius:5px;">Reset Password</a>
            <p style="margin-top:20px;font-size:small;">This link is valid for 30 minutes. If you didn’t request a reset, ignore this email.</p>
            """
            mail.send(msg)

            flash("A reset link has been sent to your email.")
        else:
            flash("❌ No account found with that email.")

        return redirect("/forgot-password")

    return render_template("forgot_password.html")

@main.route("/reset/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    email = confirm_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired.")
        return redirect("/forgot-password")

    if request.method == "POST":
        new_password = request.form["new_password"]

        # Step 2: Enforce same password strength as registration
        if (len(new_password) < 8 or len(new_password) > 16 or
            not re.search(r'[A-Z]', new_password) or
            not re.search(r'[a-z]', new_password) or
            not re.search(r'\d', new_password) or
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password)):
            flash("Password does not meet strength requirements.")
            return render_template("reset_form.html", token=token)

        # Step 3: Find the username by email from bank.users
        username = None
        for u, udata in bank.users.items():
            if udata.email == email:
                username = u
                break

        if username:
            # Step 4: Update the password inside User object
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            bank.users[username].password = hashed_pw
            bank.save_users()

            flash("Your password has been updated. You can now log in.")
            return redirect("/login")
        else:
            flash("Something went wrong.")
            return redirect("/forgot-password")

    return render_template("reset_form.html", token=token)

@main.route("/print_history")
def print_history():
    if "username" not in session:
        flash("⚠️ Session expired. Please login first.")
        return redirect("/login")

    user = bank.get_user(session["username"])

    # Show full transaction history (not sliced)
    return render_template("print_history.html", username=user.username, history=user.history)

@main.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        flash("⚠️ Session expired. Please login first.")
        return redirect("/login")

    user = bank.get_user(session["username"])

    if request.method == "POST":
        current = request.form["current_password"]
        new = request.form["new_password"]

        if not bcrypt.checkpw(current.encode(), user.password.encode()):
            flash("❌ Current password is incorrect.")
            return redirect("/change-password")

        import re
        if (len(new) < 8 or len(new) > 16 or
            not re.search(r'[A-Z]', new) or
            not re.search(r'[a-z]', new) or
            not re.search(r'\d', new) or
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', new)):
            flash("❌ New password does not meet strength requirements.")
            return redirect("/change-password")

        user.password = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
        bank.save_users()
        flash("✅ Password changed successfully.")
        return redirect("/dashboard")

    return render_template("change_password.html")

@main.app_context_processor
def inject_now():
    from datetime import datetime
    return dict(now=lambda: datetime.now())

@main.app_context_processor
def inject_bank():
    return dict(bank=bank)


