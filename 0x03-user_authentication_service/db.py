#!/usr/bin/env python3
"""
DB module for user database interactions.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from user import Base, User
from typing import TypeVar

VALID_FIELDS = ['id', 'email', 'hashed_password', 'session_id',
                'reset_token']

class DB:
    """
    DB class for managing user data in the database.
    """

    def __init__(self):
        """
        Initializes the database connection.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """
        Provides a session for database operations.

        Returns:
            Session: SQLAlchemy session.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Adds a new user to the database.

        Args:
            email (str): User's email address.
            hashed_password (str): Hashed user password.

        Returns:
            User: The newly added user.
        """
        if not email or not hashed_password:
            return
        user = User(email=email, hashed_password=hashed_password)
        session = self._session
        session.add(user)
        session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds a user based on specified criteria.

        Args:
            **kwargs: Keyword arguments specifying search criteria.

        Returns:
            User: The found user.

        Raises:
            InvalidRequestError: If invalid search criteria are provided.
            NoResultFound: If no user matches the criteria.
        """
        if not kwargs or any(x not in VALID_FIELDS for x in kwargs):
            raise InvalidRequestError
        session = self._session
        try:
            return session.query(User).filter_by(**kwargs).one()
        except Exception:
            raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates user information in the database.

        Args:
            user_id (int): User ID.
            **kwargs: Keyword arguments specifying fields to update.

        Raises:
            ValueError: If an invalid field is provided.
        """
        session = self._session
        user = self.find_user_by(id=user_id)
        for k, v in kwargs.items():
            if k not in VALID_FIELDS:
                raise ValueError
            setattr(user, k, v)
        session.commit()
