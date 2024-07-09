#!/usr/bin/env python3
"""
Basic Auth module
"""

from api.v1.auth.auth import Auth
from typing import TypeVar, List
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """
    A class to manage Basic Authentication.

    Attributes:
        None

    Methods:
        - extract_base64_authorization_header(authorization_header: str) ->
        str:
            Returns the Base64 part of the Authorization header for Basic
            Authentication.

        - decode_base64_authorization_header(base64_authorization_header: str)
        -> str:
            Decodes the Base64 string from the Authorization header.

        - extract_user_credentials(decoded_base64_authorization_header: str)
        -> (str, str):
            Extracts the user email and password from the Base64 decoded value.

        - current_user(request=None) -> TypeVar('User'):
            Overloads Auth and retrieves the User instance for a request.
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Returns the Base64 part of the Authorization header for Basic
        Authentication.

        Args:
            authorization_header (str): The Authorization header value.

        Returns:
            str: The Base64 part of the Authorization header.
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str) or
                not authorization_header.startswith("Basic")):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 string from the Authorization header.

        Args:
            base64_authorization_header (str): The Base64 Authorization
            header value.

        Returns:
            str: The decoded value.
        """
        b64_auth_header = base64_authorization_header
        if b64_auth_header and isinstance(b64_auth_header, str):
            try:
                encode = b64_auth_header.encode('utf-8')
                base = base64.b64decode(encode)
                return base.decode('utf-8')
            except binascii.Error:
                return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts the user email and password from the Base64 decoded value.

        Args:
            decoded_base64_authorization_header (str): The decoded Base64
            Authorization header value.

        Returns:
            Tuple[str, str]: The user email and password.
        """
        decoded_64 = decoded_base64_authorization_header
        if (decoded_64 and isinstance(decoded_64, str) and
                ":" in decoded_64):
            res = decoded_64.split(":", 1)
            return (res[0], res[1])
        return (None, None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Overloads Auth and retrieves the User instance for a request.

        Args:
            request: The Flask request object.

        Returns:
            TypeVar('User'): The current user.
        """
        header = self.authorization_header(request)
        b64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(b64header)
        user_creds = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_creds)
