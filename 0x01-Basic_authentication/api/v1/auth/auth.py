#!/usr/bin/env python3
"""
Authenthication class
"""

from flask import request
from typing import TypeVar, List

User = TypeVar('User')


class Auth:
    """
    A class to manage API authentication.

    Attributes:
        None

    Methods:
        - require_auth(path: str, excluded_paths: List[str]) -> bool:
            Determines whether authentication is required for a given path.

        - authorization_header(request=None) -> str:
            Retrieves the Authorization header from the request.

        - current_user(request=None) -> User:
            Retrieves the current user based on the request.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines whether authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): List of excluded paths.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        check_path = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            check_path += "/"
        if check_path in excluded_paths or path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.

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
