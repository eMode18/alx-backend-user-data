#!/usr/bin/env python3
""" Task to Encrypting Passwords with bcrypt """

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        bytes: The salted and hashed password as a bytestring.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against its hashed counterpart.

    Args:
        hashed_password (bytes): The hashed password stored in the database.
        password (str): The plaintext password to check.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
