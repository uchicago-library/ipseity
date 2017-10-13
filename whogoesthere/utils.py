from functools import wraps
from flask import abort, request

import requests
import jwt


WHOGOESTHERE_URL = None


def _check_token(token):
    """
    Check the token

    Tries to check against a provided public key (if one exists)
    """
    from . import app
    global WHOGOESTHERE_URL

    public_key = app.config.get('PUBLIC_KEY')
    if not public_key:
        # Let's go ahead and try to get it from the internet
        if WHOGOESTHERE_URL is None:
            WHOGOESTHERE_URL = app.config['WHOGOESTHERE_URL']
        r = requests.get(WHOGOESTHERE_URL+"/pubkey")
        if not r.status_code == 200:
            # No pubkey provided, couldn't get one from the server
            raise ValueError()
        public_key = r.text

    try:
        token = jwt.decode(
            token,
            public_key,
            algorithm="RS256"
        )
        return token
    except jwt.InvalidTokenError:
        return False


def _get_token():
    """
    Get the token from the response

    Expects the token to supply the token in one of the
    three ways specified in RFC 6750
    """
    # https://tools.ietf.org/html/rfc6750#section-2
    def from_header():
        # https://tools.ietf.org/html/rfc6750#section-2.1
        try:
            auth_header = request.headers['Authorization']
            if not auth_header.startswith("Bearer: "):
                raise ValueError("Malformed auth header")
            return auth_header[8:]
        except KeyError:
            # Auth isn't in the header
            return None

    def from_form():
        # https://tools.ietf.org/html/rfc6750#section-2.2
        try:
            return request.form['access_token']
        except KeyError:
            return None

    def from_query():
        # https://tools.ietf.org/html/rfc6750#section-2.3
        try:
            return request.args['access_token']
        except KeyError:
            return None

    tokens = []

    for x in [from_header, from_form, from_query]:
        token = x()
        if token:
            tokens.append(token)

    # Be a bit forgiving, don't break if they passed the
    # same token twice, even if they aren't supposed to.
    tokens = set(tokens)

    if len(tokens) > 1:
        raise ValueError("Too many tokens!")
    elif len(tokens) == 1:
        return tokens.pop()
    else:
        return None


def requires_authentication(f):
    """
    An example decorator, validates a JWT token passed
    to the decorated endpoint, and calls it, inserting the
    decoded token in the access_token kwarg.

    In the event of no token, returns a 401 response
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = _get_token()
        except ValueError:
            # Something weird went on with the token, but
            # we don't want to 500 the user.
            # https://tools.ietf.org/html/rfc6750#section-3.1 suggests
            # returning a 400 response here.
            abort(400)
        if not token:
            # No token supplied, 401
            abort(401)
        decoded_token = _check_token(token)
        if not decoded_token:
            # The token was invalid, 401
            abort(401)
        return f(*args, **kwargs, access_token=decoded_token)
    return decorated
