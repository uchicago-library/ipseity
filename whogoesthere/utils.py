from functools import wraps
from flask import abort
from flask_restful import reqparse

import jwt


PUBKEY = None


WHOGOESTHERE_URL = None


def check_token(token):
    if PUBKEY is None:
        raise AttributeError("No one set the pubkey!")
    # TODO: Implement querying the API if the pubkey is unset
    try:
        token = jwt.decode(
            token,
            PUBKEY,
            algorithm="RS256"
        )
        return token
    except jwt.InvalidTokenError:
        return False


def get_token():
    parser = reqparse.RequestParser()
    parser.add_argument('token', type=str, location=['form', 'header', 'cookies'])
    args = parser.parse_args()
    return args.get('token')


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token()
        if not token:
            abort(401)
        decoded_token = check_token(token)
        if not decoded_token:
            abort(401)
        return f(*args, **kwargs, token=decoded_token)
    return decorated
