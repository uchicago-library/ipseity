"""
whogoesthere
"""
import logging
import datetime
import json

from flask import Blueprint, jsonify, Response, abort
from flask_restful import Resource, Api, reqparse

import jwt
import bcrypt

from pymongo import MongoClient

from .exceptions import Error

__author__ = "Brian Balsamo"
__email__ = "brian@brianbalsamo.com"
__version__ = "0.0.1"


BLUEPRINT = Blueprint('whogoesthere', __name__)

BLUEPRINT.config = {}

API = Api(BLUEPRINT)

log = logging.getLogger(__name__)


@BLUEPRINT.errorhandler(Error)
def handle_errors(error):
    log.error("An error has occured: {}".format(json.dumps(error.to_dict())))
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


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
            abort(403)

        log.debug("Attempting to create user {}".format(args['user']))
        BLUEPRINT.config['authentication_db']['authentication'].insert_one(
            {
                'user': args['user'],
                'password': bcrypt.hashpw(args['pass'].encode(), bcrypt.gensalt())
            }
        )

        log.info("User {} created".format(args['user']))

        return {"success": True}


class AuthUser(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        parser.add_argument('pass', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        user = BLUEPRINT.config['authentication_db']['authentication'].find_one(
            {'user': args['user']}
        )

        log.debug("Attempting to auth {} via password".format(args['user']))

        if not user:
            log.debug("Username {} does not exist".format(args['user']))
            abort(404)
        if not bcrypt.checkpw(args['pass'].encode(), user['password']):
            log.debug("Incorrect password provided for username {}".format(args['user']))
            abort(404)
        log.debug("Assembling token for {}".format(args['user']))
        token = {
            'user': args['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(seconds=BLUEPRINT.config.get('EXP_DELTA', 86400)),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow()
        }
        authorization = BLUEPRINT.config['authorization_db']['authorization'].find_one(
            {'user': args['user']}
        )
        if authorization:
            log.debug("Username {} has associated authorization information".format(args['user']))
            token.update(authorization)
        encoded_token = jwt.encode(token, BLUEPRINT.config['PRIVATE_KEY'], algorithm='RS256')
        log.debug("User {} successfully authenticated".format(args['user']))
        return Response(encoded_token.decode())


class CheckToken(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        log.debug("Checking token: {}".format(args['token']))

        try:
            jwt.decode(
                args['token'].encode(),
                BLUEPRINT.config['PUBLIC_KEY'],
                algorithm="RS256"
            )
            log.debug("Valid token provided: {}".format(args['token']))
            return {"token_status": "valid"}
        except jwt.InvalidTokenError:
            log.debug("Invalid token provided: {}".format(args['token']))
            return {"token_status": "invalid"}


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

    authorization_client = MongoClient(
        BLUEPRINT.config.get('AUTHORIZATION_MONGO_HOST',
                             BLUEPRINT.config['AUTHENTICATION_MONGO_HOST']),
        int(BLUEPRINT.config.get("AUTHORIZATION_MONGO_PORT", 27017))
    )
    BLUEPRINT.config['authorization_db'] = \
        authorization_client[BLUEPRINT.config.get('AUTHORIZATION_MONGO_DB', 'whogoesthere')]

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
API.add_resource(AuthUser, "/auth_user")
API.add_resource(CheckToken, "/check")
