#!/usr/bin/env python3
"""
Route module for the API

This module defines the main Flask application and its routes for handling authentication.
"""

from os import getenv
from api.v1.views import app_views
from api.v1.auth.auth import Auth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.basic_auth import BasicAuth
from flask import Flask, jsonify, abort, request
from flask_cors import CORS, cross_origin


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None

# Determine the authentication type based on environment variables
if getenv("AUTH_TYPE") == "auth":
    auth = Auth()
elif getenv("AUTH_TYPE") == "basic_auth":
    auth = BasicAuth()
elif getenv("AUTH_TYPE") == "session_auth":
    auth = SessionAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """
    Handle 404 Not Found errors.

    Returns:
        Response: JSON error message with status code 404.
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """
    Handle 401 Unauthorized errors.

    Returns:
        Response: JSON error message with status code 401.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """
    Handle 403 Forbidden errors.

    Returns:
        Response: JSON error message with status code 403.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def before_request():
    """
    Execute before each request.

    - Validates authentication for protected routes.
    - Sets the current user for the request (if authenticated).
    """
    authorized_list = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/',
        '/api/v1/auth_session/login/'
    ]

    if auth and auth.require_auth(request.path, authorized_list):
        if not auth.authorization_header(request):
            abort(401)
        if auth.authorization_header(request) and not auth.session_cookie(request):
            abort(401)
        request.current_user = auth.current_user(request)
        if not auth.current_user(request):
            abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
