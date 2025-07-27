# SecureBank – Flask-Based Secure Banking System

A modern, secure, and educational banking application built using Python Flask that simulates real-world online banking workflows like user registration with email confirmation, password reset with secure tokens, file-based data storage, and OOP-based architecture.

---

## Core Features

- 🔐 User Registration with Email Confirmation (Flask-Mail + Token)
- 🔑 Secure Login with Password Hashing (bcrypt)
- 🔄 Password Reset via Email + Tokenized Reset Form
- ✅ Real-time Password Strength Validation (Frontend + Backend)
- 💳 Deposit & Withdraw Balance with Transaction History
- 🧾 Printable Transaction History
- 🌗 Light/Dark Mode Toggle with Persistent Styling
- 🧠 Username Validation + Email Uniqueness Checks
- 💼 OOP-based Design using User and Bank Classes
- 📁 JSON-based File Storage with Clean Interface Abstraction

---

## ⚙️ Tech Stack

- 🐍 Python 3.10+
- ⚙️ Flask (Blueprints, Jinja2, Flash Messaging)
- 🧵 HTML5 + CSS3 + Bootstrap 5
- ✉️ Flask-Mail (for email confirmation & reset)
- 🛡️ bcrypt for password hashing
- 🧠 itsdangerous for secure token generation
- 📦 JSON File Storage (No external DB — beginner-friendly)

---

## ✅ Key Challenges Solved

- Built full email verification + token-based password reset system without database
- Validated real-time frontend password strength using dynamic JavaScript + backend regex
- Avoided circular imports with Flask app factory pattern
- Ensured clean project modularity using Blueprint and OOP classes
- Added transaction timestamp and printing functionality using client-side print

---

## 🛠️ Setup Instructions

1. Clone the repo:

```bash
git clone 
cd securebank  
```

2. Create virtual environment:

```bash
python -m venv venv
./venv/Scripts/activate  # On Windows  
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure Gmail in app/init0.py:

```bash
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_gmail_app_password' #Use an App Password, not your primary Gmail password.
```

5. Run the server:

```bash
python run.py
```  
---
## 📜 License
MIT License © 2025 Ibrar Ul Hassan Shami | Note: Intended for educational use.
