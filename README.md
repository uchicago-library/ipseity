# whogoesthere

v0.0.1

[![Build Status](https://travis-ci.org/bnbalsamo/whogoesthere.svg?branch=master)](https://travis-ci.org/bnbalsamo/whogoesthere) [![Coverage Status](https://coveralls.io/repos/github/bnbalsamo/whogoesthere/badge.svg?branch=master)](https://coveralls.io/github/bnbalsamo/whogoesthere?branch=master)

An authentication API

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
* token (str): An encoded jwt token
#### Returns
* JSON: {"token_status": "valid||invalid"}

# Environmental Variables
* WHOGOESTHERE_PUBLIC_KEY: A public rsa key in ssh format
* WHOGOESTHERE_PRIVATE_KEY: A private rsa key in ssh format
* WHOGOESTHERE_MONGO_HOST: The IP address or hostname of the mongo server
* WHOGOESTHERE_MONGO_PORT (27017): The port the Mongo server is running on
* WHOGOESTHERE_MONGO_DB (whogoesthere): The mongo db name to use to store credentials
* WHOGOESTHERE_EXP_DELTA (86400): A length of time for tokens to remain valid, in seconds
* WHOGOESTHERE_VERBOSITY (WARN): The verbosity of the logs

# Author
Brian Balsamo <brian@brianbalsamo.com>
