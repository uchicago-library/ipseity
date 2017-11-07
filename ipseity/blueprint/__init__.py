"""
whogoesthere
"""
import logging
import datetime
from functools import wraps

from flask import Blueprint, Response, abort, g
from flask_restful import Resource, Api, reqparse

import jwt
import bcrypt

from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError

import flask_jwtlib

from .exceptions import UserAlreadyExistsError, \
    UserDoesNotExistError, IncorrectPasswordError, InvalidTokenError, \
    TokenTypeError


__author__ = "Brian Balsamo"
__email__ = "brian@brianbalsamo.com"
__version__ = "0.1.0"


BLUEPRINT = Blueprint('ipseity', __name__)

BLUEPRINT.config = {}

API = Api(BLUEPRINT)

log = logging.getLogger(__name__)


# Register some callbacks that implement
# API specific functionality in the library

# Tokens aren't valid just from being signed/well-formed
# they also have to be of type "access_token"
def check_token(token):
    x = flask_jwtlib._DEFAULT_CHECK_TOKEN(token)
    if x:
        json_token = jwt.decode(
            token.encode(),
            BLUEPRINT.config['PUBLIC_KEY'],
            algorithm="RS256"
        )
        if json_token['token_type'] == 'access_token':
            return True
    return False


flask_jwtlib.check_token = check_token


# Decorator for functions that require using a token
# which was generated from username/password authentication,
# rather than refresh token.
# Only call this _after_ flask_jwtlib.requires_authentication
def requires_password_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.json_token['authentication_method'] != 'password':
            abort(403)
        return f(*args, **kwargs)
    return decorated


# So that we don't store tokens forever
def prune_disallowed_tokens(user):
    log.debug("Pruning disallowed tokens for {}".format(user))
    user_db_doc = BLUEPRINT.config['authentication_coll'].find_one(
        {"user": user}
    )
    for x in user_db_doc['disallowed_tokens']:
        try:
            token = jwt.decode(
                x.encode(),
                BLUEPRINT.config['PUBLIC_KEY'],
                algorithm="RS256"
            )
            if token['token_type'] != 'refresh_token':
                raise TokenTypeError
        except (jwt.InvalidTokenError, TokenTypeError):
            BLUEPRINT.config['authentication_coll'].update_one(
                {'user': user_db_doc['user']},
                {"$pull": {"disallowed_tokens": x}}
            )


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

        log.debug("Attempting to create user {}".format(args['user']))
        try:
            BLUEPRINT.config['authentication_coll'].insert_one(
                {
                    'user': args['user'],
                    'password': bcrypt.hashpw(args['pass'].encode(), bcrypt.gensalt()),
                    'disallowed_tokens': []
                }
            )
        except DuplicateKeyError:
            raise UserAlreadyExistsError(args['user'])

        log.info("User {} created".format(args['user']))

        return {"success": True}


class RemoveUser(Resource):
    @flask_jwtlib.requires_authentication
    @requires_password_authentication
    def delete(self):
        log.debug("Attempting to delete user: {}".format(g.json_token['user']))

        res = BLUEPRINT.config['authentication_coll'].delete_one(
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
            try:
                token = jwt.decode(
                    args['user'].encode(),
                    BLUEPRINT.config['PUBLIC_KEY'],
                    algorithm="RS256"
                )
                log.debug("Valid token provided: {}".format(args['user']))
            except jwt.InvalidTokenError:
                log.debug("Invalid token provided: {}".format(args['user']))
                raise InvalidTokenError
            if token['token_type'] != 'refresh_token':
                raise TokenTypeError("Not a refresh token")
            user = BLUEPRINT.config['authentication_coll'].find_one(
                {"user": token['user']}
            )
            if args['user'] in user['disallowed_tokens']:
                log.debug("Refresh token {} disallowed".format(args['user']))
                raise InvalidTokenError(args['user'])
        else:
            # username/password auth
            auth_method = "password"
            user = BLUEPRINT.config['authentication_coll'].find_one(
                {'user': args['user']}
            )
            if not user:
                log.debug("Username {} does not exist".format(args['user']))
                raise UserDoesNotExistError(args['user'])
            if not bcrypt.checkpw(args['pass'].encode(), user['password']):
                log.debug("Incorrect password provided for username {}".format(args['user']))
                raise IncorrectPasswordError(args['user'])

        # Prune the users disallowed tokens, so no invalid tokens
        # or old tokens stick in the DB
        prune_disallowed_tokens(user['user'])
        # If we got to here we found a user, either by refresh token or
        # username/password auth
        log.debug("Assembling token for {}".format(args['user']))
        token = {
            'user': user['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(
                seconds=BLUEPRINT.config.get('ACCESS_EXP_DELTA', 72000)  # 20 hours
            ),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow(),
            'authentication_method': auth_method,
            'token_type': 'access_token'
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
            if token['token_type'] != "access_token":
                raise TokenTypeError
            log.debug("Valid token provided: {}".format(args['access_token']))
            return token
        except (jwt.InvalidTokenError, TokenTypeError):
            log.debug("Invalid token provided: {}".format(args['access_token']))
            raise InvalidTokenError


class Test(Resource):
    @flask_jwtlib.requires_authentication
    def get(self):
        return g.json_token


class ChangePassword(Resource):
    @flask_jwtlib.requires_authentication
    @requires_password_authentication
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('new_pass', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        BLUEPRINT.config['authentication_coll'].update_one(
            {'user': g.json_token['user']},
            {'$set': {'password': bcrypt.hashpw(args['new_pass'].encode(), bcrypt.gensalt())}}
        )

        return {"success": True}


class RefreshToken(Resource):
    @flask_jwtlib.requires_authentication
    @requires_password_authentication
    def get(self):
        token = {
            'user': g.json_token['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(
                seconds=BLUEPRINT.config.get('REFRESH_EXP_DELTA', 2592000)  # a month
            ),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow(),
            'token_type': 'refresh_token'
        }
        encoded_token = jwt.encode(token, BLUEPRINT.config['PRIVATE_KEY'], algorithm='RS256')
        prune_disallowed_tokens(g.json_token['user'])
        return Response(encoded_token)

    @flask_jwtlib.requires_authentication
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('refresh_token', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        try:
            token = jwt.decode(
                args['refresh_token'].encode(),
                BLUEPRINT.config['PUBLIC_KEY'],
                algorithm="RS256"
            )
        except jwt.InvalidTokenError:
            raise InvalidTokenError()
        if token['token_type'] != 'refresh_token' or \
                token['user'] != g.json_token['user']:
            raise TokenTypeError

        res = BLUEPRINT.config['authentication_coll'].update_one(
            {'user': g.json_token['user']},
            {'$push': {'disallowed_tokens': args['refresh_token']}}
        )

        if res.modified_count > 0:
            prune_disallowed_tokens(g.json_token['user'])
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
        BLUEPRINT.config['MONGO_HOST'],
        int(BLUEPRINT.config.get('MONGO_PORT', 27017))
    )
    authentication_db = \
        authentication_client[BLUEPRINT.config.get('MONGO_DB', 'ipseity')]

    BLUEPRINT.config['authentication_coll'] = \
        authentication_db['authentication']

    BLUEPRINT.config['authentication_coll'].create_index(
        [('user', ASCENDING)],
        unique=True
    )

    flask_jwtlib.set_permanent_pubkey(BLUEPRINT.config['PUBLIC_KEY'])

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
