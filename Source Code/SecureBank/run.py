import os
import sys
sys.path.append('G:/CyberSecurity/banking-flask-app')

from app.init0 import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
