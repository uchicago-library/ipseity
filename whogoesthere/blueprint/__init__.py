"""
whogoesthere
"""
import logging
import datetime
import json
from functools import wraps
from uuid import uuid4

from flask import Blueprint, jsonify, Response, request, abort, g
from flask_restful import Resource, Api, reqparse

import jwt
import bcrypt

from pymongo import MongoClient

from .exceptions import Error, UserAlreadyExistsError, \
    UserDoesNotExistError, IncorrectPasswordError, InvalidTokenError

__author__ = "Brian Balsamo"
__email__ = "brian@brianbalsamo.com"
__version__ = "0.0.1"


BLUEPRINT = Blueprint('whogoesthere', __name__)

BLUEPRINT.config = {}

API = Api(BLUEPRINT)

log = logging.getLogger(__name__)


def _check_token(token):
    """
    Check the token

    Tries to check against a provided public key (if one exists)
    """
    try:
        token = jwt.decode(
            token,
            BLUEPRINT.config['PUBLIC_KEY'],
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


# Decorator for use on endpoints
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
        json_token = _check_token(token)
        if not json_token:
            # The token was invalid, 401
            abort(401)
        g.raw_token = token
        g.json_token = json_token
        return f(*args, **kwargs)
    return decorated


# Decorator for functions that require using a token
# which was generated from username/password authentication,
# rather than refresh token.
def requires_password_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.json_token['authentication_method'] != 'password':
            abort(403)
        return f(*args, **kwargs)
    return decorated


@BLUEPRINT.errorhandler(Error)
def handle_errors(error):
    log.error("An error has occured: {}".format(json.dumps(error.to_dict())))
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@BLUEPRINT.before_request
def set_g_defaults():
    """
    Set the defaults for the authentication variables
    """
    g.authenticated = False
    g.raw_token = None
    g.json_token = None


class Root(Resource):
    def get(self):
        return {"Status": "Not broken!"}


class Version(Resource):
    def get(self):
        return {"version": __version__}


class PublicKey(Resource):
    def get(self):
        return Response(BLUEPRINT.config['PUBLIC_KEY'])


class MakeUser(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        parser.add_argument('pass', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        log.debug("Attempting to create user: {}".format(args['user']))

        if BLUEPRINT.config['authentication_db']['authentication'].find_one({'user': args['user']}):
            log.info("User creation failed, user {} already exists".format(args['user']))
            raise UserAlreadyExistsError(args['user'])

        log.debug("Attempting to create user {}".format(args['user']))
        BLUEPRINT.config['authentication_db']['authentication'].insert_one(
            {
                'user': args['user'],
                'password': bcrypt.hashpw(args['pass'].encode(), bcrypt.gensalt()),
                'refresh_tokens': []
            }
        )

        log.info("User {} created".format(args['user']))

        return {"success": True}


class RemoveUser(Resource):
    @requires_authentication
    @requires_password_authentication
    def delete(self):
        log.debug("Attempting to delete user: {}".format(g.json_token['user']))

        res = BLUEPRINT.config['authentication_db']['authentication'].delete_one(
            {
                'user': g.json_token['user']
            }
        )

        if res.deleted_count == 1:
            # success
            log.info("User {} deleted".format(g.json_token['user']))
            return {"success": True}
        else:
            # fail
            log.info("Deletetion attempt on user {} failed".format(g.json_token['user']))
            return {"success": False}


class AuthUser(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        parser.add_argument('pass', type=str, default=None,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()
        log.debug("Attempting to auth {}".format(args['user']))

        auth_method = None
        if not args['pass']:
            # Token based auth
            auth_method = "refresh_token"
            user = BLUEPRINT.config['authentication_db']['authentication'].find_one(
                {"refresh_tokens": args['user']}
            )
            if not user:
                log.debug("Refresh token {} does not exist".format(args['user']))
                raise InvalidTokenError(args['user'])
        else:
            # username/password auth
            auth_method = "password"
            user = BLUEPRINT.config['authentication_db']['authentication'].find_one(
                {'user': args['user']}
            )
            if not user:
                log.debug("Username {} does not exist".format(args['user']))
                raise UserDoesNotExistError(args['user'])
            if not bcrypt.checkpw(args['pass'].encode(), user['password']):
                log.debug("Incorrect password provided for username {}".format(args['user']))
                raise IncorrectPasswordError(args['user'])

        # If we got to here we found a user, either by refresh token or
        # username/password auth
        log.debug("Assembling token for {}".format(args['user']))
        token = {
            'user': user['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(seconds=BLUEPRINT.config.get('EXP_DELTA', 86400)),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow(),
            'authentication_method': auth_method
        }

        encoded_token = jwt.encode(token, BLUEPRINT.config['PRIVATE_KEY'], algorithm='RS256')
        log.debug("User {} successfully authenticated".format(args['user']))
        return Response(encoded_token.decode())


class CheckToken(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('access_token', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        log.debug("Checking token: {}".format(args['access_token']))

        try:
            token = jwt.decode(
                args['access_token'].encode(),
                BLUEPRINT.config['PUBLIC_KEY'],
                algorithm="RS256"
            )
            log.debug("Valid token provided: {}".format(args['access_token']))
            return token
        except jwt.InvalidTokenError:
            log.debug("Invalid token provided: {}".format(args['access_token']))
            raise InvalidTokenError


class Test(Resource):
    @requires_authentication
    def get(self):
        return g.json_token


class ChangePassword(Resource):
    @requires_authentication
    @requires_password_authentication
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('new_pass', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        BLUEPRINT.config['authentication_db']['authentication'].update_one(
            {'user': g.json_token['user']},
            {'$set': {'password': bcrypt.hashpw(args['new_pass'].encode(), bcrypt.gensalt())}}
        )

        return {"success": True}


class RefreshToken(Resource):
    @requires_authentication
    @requires_password_authentication
    def get(self):
        refresh_token = uuid4().hex
        BLUEPRINT.config['authentication_db']['authentication'].update_one(
            {'user': g.json_token['user']},
            {'$push': {'refresh_tokens': refresh_token}}
        )
        return Response(refresh_token)

    @requires_authentication
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('refresh_token', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        res = BLUEPRINT.config['authentication_db']['authentication'].update_one(
            {'user': g.json_token['user']},
            {'$pull': {'refresh_tokens': args['refresh_token']}}
        )

        if res.modified_count > 0:
            return {"success": True}
        else:
            raise InvalidTokenError()


@BLUEPRINT.record
def handle_configs(setup_state):
    app = setup_state.app
    BLUEPRINT.config.update(app.config)
    if BLUEPRINT.config.get('DEFER_CONFIG'):
        log.debug("DEFER_CONFIG set, skipping configuration")
        return

    authentication_client = MongoClient(
        BLUEPRINT.config['AUTHENTICATION_MONGO_HOST'],
        int(BLUEPRINT.config.get('AUTHENTICATION_MONGO_PORT', 27017))
    )
    BLUEPRINT.config['authentication_db'] = \
        authentication_client[BLUEPRINT.config.get('AUTHENTICATION_MONGO_DB', 'whogoesthere')]

    if BLUEPRINT.config.get("VERBOSITY"):
        log.debug("Setting verbosity to {}".format(str(BLUEPRINT.config['VERBOSITY'])))
        logging.basicConfig(level=BLUEPRINT.config['VERBOSITY'])
    else:
        log.debug("No verbosity option set, defaulting to WARN")
        logging.basicConfig(level="WARN")


API.add_resource(Root, "/")
API.add_resource(Version, "/version")
API.add_resource(PublicKey, "/pubkey")
API.add_resource(MakeUser, "/make_user")
API.add_resource(RemoveUser, "/del_user")
API.add_resource(AuthUser, "/auth_user")
API.add_resource(CheckToken, "/check")
API.add_resource(Test, "/test")
API.add_resource(ChangePassword, "/change_pass")
API.add_resource(RefreshToken, "/refresh_token")
