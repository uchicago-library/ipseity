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

# Environmental Variables
* None

# Author
Brian Balsamo <brian@brianbalsamo.com>
