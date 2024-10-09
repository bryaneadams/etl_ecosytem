from __future__ import annotations

import os
import requests

from airflow.www.fab_security.manager import AUTH_OAUTH
from airflow.www.security import AirflowSecurityManager

basedir = os.path.abspath(os.path.dirname(__file__))

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None


# The authentication type

AUTH_TYPE = AUTH_OAUTH

# Uncomment to setup Full admin role name
AUTH_ROLE_ADMIN = "Admin"

# Uncomment and set to desired role to enable access without authentication
# AUTH_ROLE_PUBLIC = 'Viewer'

# Will allow user self registration
AUTH_USER_REGISTRATION = True
# Needed if you want to sync people's roles when logging in
AUTH_ROLES_SYNC_AT_LOGIN = True

# The recaptcha it's automatically enabled for user self registration is active and the keys are necessary
# RECAPTCHA_PRIVATE_KEY = PRIVATE_KEY
# RECAPTCHA_PUBLIC_KEY = PUBLIC_KEY

# The default user self registration role
# AUTH_USER_REGISTRATION_ROLE = "Public"

OAUTH_PROVIDERS = [
    {
        "name": "google",
        "token_key": "access_token",
        "icon": "fa-google",
        "remote_app": {
            "api_base_url": "https://www.googleapis.com/oauth2/v2/",
            "client_kwargs": {"scope": "email profile"},
            "access_token_url": "https://accounts.google.com/o/oauth2/token",
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "request_token_url": None,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_SECRET"),
            "authorize_url_params": {
                "redirect_uri": os.getenv("REDIRECT_URI"),
                "scope": "email profile",
            },
        },
    }
]

AUTH_ROLES_MAPPING = {
    "Viewer": ["Viewer"],
    "Admin": ["Admin"],
    "User": ["User"],
    "Public": ["Public"],
    "Op": ["Op"],
}


class CustomSecurityManager(AirflowSecurityManager):
    """Used to override the login manager and provide user information from google
    This will assign approved default roles.
    """

    def oauth_user_info(self, provider: str, response: dict) -> dict:
        """Used to parse user information for github

        Args:
            provider (str): the provider you are using for OAUTH2, only needed if you want to be able
            to switch between providers
            response (dict): the default payload from your OAUTH2 provider, this changes from provider to provider

        Returns:
            dict: user information for FAB to login,update, and create user
        """

        authorized_users = os.getenv("AUTHORIZED_USERS").split(",")
        google_endpoint = os.getenv("GOOGLE_URL")

        access_token = response["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        user_info = requests.get(google_endpoint, headers=headers).json()

        if user_info.get("email_verified"):
            if user_info.get("email") in authorized_users:
                information = {
                    "username": user_info.get("name"),
                    "email": user_info.get("email"),
                    "first_name": user_info.get("given_name"),
                    "last_name": user_info.get("family_name"),
                    "role_keys": ["Admin"],
                }

                return information

        return {}


SECURITY_MANAGER_CLASS = CustomSecurityManager
