from flask import Flask
from flask_mail import Mail
from datetime import timedelta
import secrets
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    app.permanent_session_lifetime = timedelta(minutes=2)
    
    # Email Config (use your Gmail app password)
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    mail.init_app(app)
    from app.routes import main
    app.register_blueprint(main)
    return app
