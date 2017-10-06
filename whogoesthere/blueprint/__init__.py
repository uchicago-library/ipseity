"""
whogoesthere
"""
import logging
import datetime

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

        if BLUEPRINT.config['db']['authentication'].find_one({'user': args['user']}):
            abort(403)

        BLUEPRINT.config['db']['authentication'].insert_one(
            {
                'user': args['user'],
                'password': bcrypt.hashpw(args['pass'].encode(), bcrypt.gensalt())
            }
        )

        return {"success": True}


class AuthUser(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        parser.add_argument('pass', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        user = BLUEPRINT.config['db']['authentication'].find_one(
            {'user': args['user']}
        )

        if not user:
            abort(404)
        if not bcrypt.checkpw(args['pass'].encode(), user['password']):
            abort(404)
        token = {
            'user': args['user'],
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(seconds=BLUEPRINT.config.get('EXP_DELTA', 86400)),
            'nbf': datetime.datetime.utcnow(),
            'iat': datetime.datetime.utcnow()
        }
        authorization = BLUEPRINT.config['db']['authorization'].find_one(
            {'user': args['user']}
        )
        if authorization:
            token.update(authorization)
        encoded_token = jwt.encode(token, BLUEPRINT.config['PRIVATE_KEY'], algorithm='RS256')
        return Response(encoded_token.decode())


class CheckToken(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token', type=str, required=True,
                            location=['form', 'header', 'cookies'])
        args = parser.parse_args()

        try:
            jwt.decode(
                args['token'].encode(),
                BLUEPRINT.config['PUBLIC_KEY'],
                algorithm="RS256"
            )
            return {"token_status": "valid"}
        except:
            return {"token_status": "invalid"}


@BLUEPRINT.record
def handle_configs(setup_state):
    app = setup_state.app
    BLUEPRINT.config.update(app.config)
    if BLUEPRINT.config.get('DEFER_CONFIG'):
        log.debug("DEFER_CONFIG set, skipping configuration")
        return

    client = MongoClient(
        BLUEPRINT.config['MONGO_HOST'],
        int(BLUEPRINT.config.get('MONGO_PORT', 27017))
    )
    BLUEPRINT.config['db'] = client[BLUEPRINT.config.get('MONGO_DB', 'whogoesthere')]

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
