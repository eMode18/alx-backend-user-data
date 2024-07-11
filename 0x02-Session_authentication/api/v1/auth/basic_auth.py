#!/usr/bin/env python3
"""
Basic Auth module

This module provides the BasicAuth class for handling basic authentication.
"""

from api.v1.auth.auth import Auth
from typing import TypeVar, Tuple
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """
    BasicAuth class for handling basic authentication.

    Methods:
        - extract_base64_authorization_header(authorization_header: str) ->
        str:
            Returns the Base64 part of the Authorization header for Basic
            Authentication.
        - decode_base64_authorization_header(base64_authorization_header: str)
        -> str:
            Decodes the Base64 string from the Authorization header.
        - extract_user_credentials(decoded_base64_authorization_header: str)
        -> Tuple[str, str]:
            Extracts user email and password from the decoded Base64 value.
        - current_user(request=None) -> TypeVar('User'):
            Retrieves the User instance for a request.
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Returns the Base64 part of the Authorization
        header for a Basic Authentication.
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str) or
                not authorization_header.startswith("Basic")):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Returns the decoded value of a Base64
        string base64_authorization_header.
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
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        Extracts the user email and password from the Base64 decoded value.
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
        """
        header = self.authorization_header(request)
        b64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(b64header)
        user_creds = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_creds)
