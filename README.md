# whogoesthere

v0.0.1

[![Build Status](https://travis-ci.org/bnbalsamo/whogoesthere.svg?branch=master)](https://travis-ci.org/bnbalsamo/whogoesthere) [![Coverage Status](https://coveralls.io/repos/github/bnbalsamo/whogoesthere/badge.svg?branch=master)](https://coveralls.io/github/bnbalsamo/whogoesthere?branch=master)

An authentication API microservice

[Authentication != Authorization](https://serverfault.com/questions/57077/what-is-the-difference-between-authentication-and-authorization)

This microservice utilizes JWTs to provide authentication assurances to other services. Services may either use this API, or a locally cached copy of the services public key, in order to validate JWTs minimally containg a users name.

Don't know what a JSON Web Token (JWT) is? Read about them [here](https://jwt.io/)

Credentials are held in a MongoDB collection. Passwords are salted/hashed via [bcrypt](https://pypi.python.org/pypi/bcrypt).

Tokens creation and validation is handled via [PyJWT](https://pypi.python.org/pypi/PyJWT)

## Warnings

**DO NOT RUN THIS SERVER OVER HTTP** - user passwords will be transmitted in plaintext, use HTTPS

**DO NOT LEAVE YOUR MONGO INSTANCE ACCESSIBLE TO THE INTERNET WITHOUT AUTHENTICATION** - the mongo data is cannonical, while all passwords are stored hashed usernames will be exposed, and passwords could be changed/users deleted/claims altered.

**DO NOT EXPOSE YOUR PRIVATE KEY** - With knowledge of the private key anyone can create valid tokens for any user.

**DO NOT RUN THE CURRENT DOCKERFILE IN PRODUCTION** - the current dockerfile runs the API over HTTP for development/testing purposes

Things this API can do:
* Store username/passwords, validate logins

Things this API can't do:
* Limit who can create an account
* Allow one user to interact with anothers account
    * creation
    * deletion
    * password change
    * etc

Things you can do with either a sidecar authentication/claims API that manipulates the underlying mongo or the ability to craft valid tokens for users without their passwords (aka, having the secret key):
* See above


# Debug Quickstart
Set environmental variables appropriately
```
./debug.sh
```

# Docker Quickstart
Inject environmental variables appropriately at either buildtime or runtime
```
# docker build . -t whogoesthere
# docker run -p 5000:80 whogoesthere --name my_whogoesthere
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
* WHOGOESTHERE_AUTHENTICATION_MONGO_HOST: The IP address or hostname of the mongo server for authentication data
* WHOGOESTHERE_PUBLIC_KEY: A public rsa key in ssh format
* WHOGOESTHERE_PRIVATE_KEY: A private rsa key in ssh format
## Optional (defaults)
* WHOGOESTHERE_AUTHENTICATION_MONGO_PORT (27017): The port the Mongo server is running on
* WHOGOESTHERE_AUTHENTICATION_MONGO_DB (whogoesthere): The mongo db name to use to store credentials
* WHOGOESTHERE_CLAIMS_MONGO_HOST ($WHOGOESTHERE_AUTHENTICATION_MONGO_HOST): The IP address or hostname of the mongo server for claims data
* WHOGOESTHERE_CLAIMS_MONGO_PORT (27017): The port the Mongo server is running on
* WHOGOESTHERE_CLAIMS_MONGO_DB (whogoesthere): The mongo db name to use to store credentials
* WHOGOESTHERE_EXP_DELTA (86400): A length of time for tokens to remain valid, in seconds
* WHOGOESTHERE_VERBOSITY (WARN): The verbosity of the logs

# Author
Brian Balsamo <brian@brianbalsamo.com>
