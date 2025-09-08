#!/usr/bin/env python3
"""
Install required dependencies for YouTube Live Dashboard
"""
import subprocess
import sys

def install_requirements():
    """Install required packages from requirements.txt"""
    try:
        print("Installing required dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All dependencies installed successfully!")
        print("\nYou can now run the server with: python app.py")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("\nPlease install manually:")
        print("pip install Flask==2.3.3 Flask-CORS==4.0.0 google-auth==2.23.4 google-auth-oauthlib==1.1.0 google-auth-httplib2==0.1.1 google-api-python-client==2.108.0")
    except FileNotFoundError:
        print("❌ pip not found. Please install pip first.")
        print("Or install manually:")
        print("pip install Flask==2.3.3 Flask-CORS==4.0.0 google-auth==2.23.4 google-auth-oauthlib==1.1.0 google-auth-httplib2==0.1.1 google-api-python-client==2.108.0")

if __name__ == "__main__":
    install_requirements()
