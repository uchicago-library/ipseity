# whogoesthere

v0.0.1

[![Build Status](https://travis-ci.org/bnbalsamo/whogoesthere.svg?branch=master)](https://travis-ci.org/bnbalsamo/whogoesthere) [![Coverage Status](https://coveralls.io/repos/github/bnbalsamo/whogoesthere/badge.svg?branch=master)](https://coveralls.io/github/bnbalsamo/whogoesthere?branch=master)

An authentication API

[Authentication != Authorization](https://serverfault.com/questions/57077/what-is-the-difference-between-authentication-and-authorization)

This package also provides some utilities for utilizing a remote whogoesthere server in your own APIs, as well as some minimal functional decorators for requiring authentication, or implementing your own authorization decorator.


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
* JSON: The token, if validation occured or 401

# Environmental Variables
## Required
* WHOGOESTHERE_AUTHENTICATION_MONGO_HOST: The IP address or hostname of the mongo server for authentication data
* WHOGOESTHERE_PUBLIC_KEY: A public rsa key in ssh format
* WHOGOESTHERE_PRIVATE_KEY: A private rsa key in ssh format
## Optional (defaults)
* WHOGOESTHERE_AUTHENTICATION_MONGO_PORT (27017): The port the Mongo server is running on
* WHOGOESTHERE_AUTHENTICATION_MONGO_DB (whogoesthere): The mongo db name to use to store credentials
* WHOGOESTHERE_AUTHORIZATION_MONGO_HOST ($WHOGOESTHERE_AUTHENTICATION_MONGO_HOST): The IP address or hostname of the mongo server for authorization data
* WHOGOESTHERE_AUTHORIZATION_MONGO_PORT (27017): The port the Mongo server is running on
* WHOGOESTHERE_AUTHORIZATION_MONGO_DB (whogoesthere): The mongo db name to use to store credentials
* WHOGOESTHERE_EXP_DELTA (86400): A length of time for tokens to remain valid, in seconds
* WHOGOESTHERE_VERBOSITY (WARN): The verbosity of the logs
## Strictly for the utils
* WHOGOESTHERE_URL: A remote URL to retrieve a public key from, which will be employed by the decorators in order to validate tokens on incoming requests if a public key isn't provided

# Author
Brian Balsamo <brian@brianbalsamo.com>
