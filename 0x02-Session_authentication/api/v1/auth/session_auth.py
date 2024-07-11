#!/usr/bin/env python3
"""
Session Auth module

This module provides the SessionAuth class for handling session-based authentication.
"""

from api.v1.auth.auth import Auth
from typing import TypeVar
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    """
    SessionAuth class for handling session-based authentication.

    Methods:
        - create_session(user_id: str = None) -> str:
            Creates a Session ID for a given user ID.
        - user_id_for_session_id(session_id: str = None) -> str:
            Returns the User ID associated with a given Session ID.
        - current_user(request=None) -> TypeVar('User'):
            Retrieves the User instance for a given request.
    """
    def create_session(self, user_id: str = None) -> str:
        """
        Creates a Session ID for a user ID.

        Args:
            user_id (str): The user ID.

        Returns:
            str: The generated session ID.
        """
        if not user_id or type(user_id) != str:
            return None
        session_id = str(uuid4())
        SessionAuth.user_id_by_session_id[user_id] = session_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns the User ID associated with a given Session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            str: The corresponding user ID or None if not found.
        """
        if not session_id or type(session_id) != str:
            return None
        return SessionAuth.user_id_by_session_id.get(session_id, None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a given request.

        Args:
            request: The request object (optional).

        Returns:
            TypeVar('User'): The User instance or None if not found.
        """
        if request:
            session_cookie = self.session_cookie(request)
            if session_cookie:
                user_id = self.user_id_for_session_id(session_cookie)
                return User.get(user_id)
