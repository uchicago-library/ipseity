# ipseity

v0.3.0

[![Build Status](https://travis-ci.org/uchicago-library/ipseity.svg?branch=master)](https://travis-ci.org/uchicago-library/ipseity) [![Coverage Status](https://coveralls.io/repos/github/uchicago-library/ipseity/badge.svg?branch=master)](https://coveralls.io/github/uchicago-library/ipseity?branch=master)


ipseity (noun): selfhood; individual identity, individuality


An authentication API microservice

[Authentication != Authorization](https://serverfault.com/questions/57077/what-is-the-difference-between-authentication-and-authorization)

This microservice utilizes JWTs to provide authentication assurances to other services. Services may either use this API, or a locally cached copy of the services public key, in order to validate JWTs containing a users name, as well as some minimal subsidiary information.

Don't know what a JSON Web Token (JWT) is? Read about them [here](https://jwt.io/)

Credentials are held in a MongoDB collection. Passwords are salted/hashed via [bcrypt](https://pypi.python.org/pypi/bcrypt).

Tokens creation and validation is handled via [PyJWT](https://pypi.python.org/pypi/PyJWT) in the server, and should probably be handled by it in your client too.

I've written (and ipseity uses behind the scenes) a [handy helper library](https://github.com/uchicago-library/flask_jwtlib) that may also be of interest to clients. It uses PyJWT itself.

To see a working client/server demo:
```
$ docker-compose up -d
$ firefox http://localhost:5000
```

## Warnings

**DO NOT RUN THIS SERVER OVER HTTP** - user passwords will be transmitted in plaintext, use HTTPS

**DO NOT LEAVE YOUR MONGO INSTANCE ACCESSIBLE TO THE INTERNET WITHOUT AUTHENTICATION** - the mongo data is cannonical, while all passwords are stored hashed, usernames will be exposed, and passwords could be changed/users deleted.

**DO NOT EXPOSE YOUR PRIVATE KEY** - With knowledge of the private key anyone can create valid tokens for any user.

**DO NOT RUN THE CURRENT DOCKERFILE IN PRODUCTION** - the current dockerfile runs the API over HTTP for development/testing purposes

Things this API can do:
* Store username/passwords, validate logins
* Generate access tokens
* Generate/Revoke refresh tokens

Things this API can't do:
* Limit who can create an account
* Allow one user to interact with anothers account
    * creation
    * deletion
    * password change
    * etc
* Store authorization information

# Debug Quickstart
Set environmental variables appropriately
```
./debug.sh
```

# Docker Quickstart
Inject environmental variables appropriately at either buildtime or runtime
```
# docker build . -t ipseity 
# docker run -p 5000:80 ipseity --name my_ipseity
```

# Endpoints
## /
### GET
#### Parameters
* None
#### Returns
* JSON: {"status": "Not broken!"}

## /version
### GET
#### Parameters
* None
#### Returns
* JSON: {"version": "$version_number"}

## /pubkey
### GET
#### Parameters
* None
#### Returns
* str: The public key

## /make_user
### POST
#### Parameters
* user (str): The user name to create
* pass (str): The password to associate with the user name
#### Returns
* JSON: {"success": True||False}

## /auth_user
### GET
#### Parameters
* user (str): The user name
* pass (str): The password
#### Returns
* str: The encoded JWT token

## /check
### GET
#### Parameters
* access_token (str): An encoded jwt token
#### Returns
* JSON: A decoded JWT token, or a 400

## /test
### GET
#### Parameters
* access_token (str): An encoded jwt token
#### Returns
* JSON: The token, if validation occured, or 401

# Environmental Variables
## Required
* IPSEITY_MONGO_HOST: The IP address or hostname of the mongo server for authentication data
* IPSEITY_PUBLIC_KEY: A public rsa key in ssh format
* IPSEITY_PRIVATE_KEY: A private rsa key in ssh format
## Optional (defaults)
* IPSEITY_MONGO_PORT (27017): The port the Mongo server is running on
* IPSEITY_MONGO_DB (ipseity): The mongo db name to use to store the collection
* IPSEITY_MONGO_COLLECTION (authentication): The mongo collection which stores credentials
* IPSEITY_ACCESS_EXP_DELTA (72000): A length of time for access tokens to remain valid, in seconds
* IPSEITY_REFRESH_EXP_DELTA (2592000): A length of time for refresh tokens to remain valid, in seconds
* IPSEITY_VERBOSITY (WARN): The verbosity of the logs

# Author
Brian Balsamo <brian@brianbalsamo.com>
