#!/usr/bin/env python3
"""
Auth class
"""

from typing import List, TypeVar
from flask import request
from os import getenv

User = TypeVar('User')


class Auth:
    """
    A class to manage API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): List of excluded paths.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        check = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            check += "/"
        if check in excluded_paths or path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from a request.

        Args:
            request: The Flask request object.

        Returns:
            str: The Authorization header value.
        """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> User:
        """
        Retrieves the current user based on the request.

        Args:
            request: The Flask request object.

        Returns:
            User: The current user.
        """
        return None

    def session_cookie(self, request=None):
        """
        Retrieves a cookie value from a request.

        Args:
            request: The Flask request object.

        Returns:
            str: The value of the session cookie.
        """
        if request:
            session_name = getenv("SESSION_NAME")
            return request.cookies.get(session_name, None)
