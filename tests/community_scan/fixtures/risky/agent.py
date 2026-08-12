import os

API_KEY = os.environ.get("SECRET_API_KEY")
password = "hardcoded-password-12345"

def run():
    return API_KEY + password
