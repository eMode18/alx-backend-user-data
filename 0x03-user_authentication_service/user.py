#!/usr/bin/env python3
""" User module

This module defines the User class for representing users in the system.
"""

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()

class User(Base):
    """
    Represents a user in the system.

    Attributes:
        id (int): The unique identifier for the user.
        email (str): The user's email address.
        hashed_password (str): The hashed password for authentication.
        session_id (str): The active session ID (if logged in).
        reset_token (str): Token for password reset (if requested).
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        """
        Returns a string representation of the user.

        Returns:
            str: A formatted string with user information.
        """
        return f"User: id={self.id}"
