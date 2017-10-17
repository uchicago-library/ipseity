"""
Demo of using a whogoesthere JWT server for authentication.

# Required env vars
* WHOGOESTHERE_URL: The URL of the whogoesthere server
* SESSION_MONGODB_HOST: The address of a mongo server
    to use to store sessions

# Optional env vars
* SERVER_NAME: Change this to what the external server
    name looks like, primarily for use in dockerized
    environmnets.
* SECRET_KEY: Manually specify this flask apps secret key
    which is used to store sessions. Important if you want
    to run multiple instances sharing sessions.
* SESSION_MONGODB_PORT: The port your $SESSION_MONGODB_HOST
    is listening on, if not 27017
* WHOGOESTHERE_PUBKEY: The pubkey of the whogoesthere server,
    providing it explicitly will prevent periodically retrieving
    it from the remote server
* PUBKEY_CACHE_TIMEOUT: How long, in seconds, before we check
    the whogoesthere server to refresh the pubkey cache
    (if in use). Defaults to 300 seconds (5 minutes)
"""

from os import environ
from uuid import uuid4
import datetime
from functools import wraps
from flask import Flask, request, redirect, make_response, session, \
    render_template, url_for
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo
import requests
import jwt
from pymongo import MongoClient

# =====
# App instantiation and configuration
# =====

app = Flask(__name__)

# We have to set a secret key, so we can
# use sessions to store the token after
# the user logs in.
# If it's not specified use a random one
app.secret_key = environ.get('SECRET_KEY') or uuid4().hex

# Dockerizing this breaks CSRF for complicated reasons
# So, for the demo, I'm disabling it. In production
# probably don't.
app.config['WTF_CSRF_ENABLED'] = False

# We need to implement server side
# sessions, because we're storing tokens
# in them which we don't want transmitted
# through cookies (the default session
# implementation)
app.config['SESSION_TYPE'] = 'mongodb'
app.config['SESSION_MONGODB'] = \
    MongoClient(
        environ['SESSION_MONGODB_HOST'],
        environ.get('SESSION_MONGODB_PORT', 27017)
    )

# Instantiate our new session backend
Session(app)

# =====
# pubkey cache in the global namespace
# =====
# We store the key itself and the last time
# it was retrieved at, so we can keep it fresh
# if we're pulling from the server
pubkey_tuple = None
# If we explicitly set the pubkey never check it from the server
if environ.get("WHOGOESTHERE_PUBKEY"):
    pubkey_tuple = (environ['WHOGOESTHERE_PUBKEY'], datetime.datetime.max)


class LoginForm(FlaskForm):
    user = StringField(
        'user',
        validators=[
            DataRequired(),
            Length(min=3)
        ]
    )
    # Password field can be completely blank, for token logins
    password = PasswordField(
        'pass',
        validators=[]
    )


class RegistrationForm(FlaskForm):
    user = StringField(
        'user',
        validators=[
            DataRequired(),
            Length(min=3)
        ]
    )
    password = PasswordField(
        'pass',
        validators=[
            DataRequired(),
            Length(min=3),
            EqualTo('confirm', message='Passwords must match')
        ]
    )
    confirm = PasswordField(
        'repeat_password'
    )


class DeauthRefreshTokenForm(FlaskForm):
    refresh_token = StringField(
        'refresh_token',
        validators=[
            DataRequired()
        ]
    )


def check_token(token, pubkey):
    """
    Check the token
    Assumes it's in the format the whogoesthere server returns
    """
    try:
        token = jwt.decode(
            token,
            pubkey,
            algorithm="RS256"
        )
        return token
    except jwt.InvalidTokenError:
        return False


def _get_token():
    """
    Get the token from the response
    Expects the response to supply the token in one of the
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


def get_token():
    # Our app also stores tokens in the session
    # after the initial login, so we wrap the RFCs
    # token retrieval impementations in a backup
    # that checks the session
    token = _get_token()
    if not token:
        token = session.get('access_token', None)
    return token


def pubkey():
    # A function which returns the pubkey,
    # "freshened" if required.
    global pubkey_tuple
    if not pubkey_tuple or \
            (datetime.datetime.now() - pubkey_tuple[1]) > \
            datetime.timedelta(seconds=(environ.get("PUBKEY_CACHE_TIMEOUT", 300))):
        # Refresh the pubkey tuple
        pubkey_resp = requests.get(environ['WHOGOESTHERE_URL'] + "/pubkey")
        if pubkey_resp.status_code != 200:
            if not pubkey_tuple:
                raise ValueError("Pubkey couldn't be retrieved!")
        pubkey = pubkey_resp.text
        pubkey_tuple = (pubkey, datetime.datetime.now())
    return pubkey_tuple[0]


# Wrapper for when a user _must_ be authenticated
def requires_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token formatting
            return redirect("/login")
        if not token:
            # Token isn't in the request or the session
            return redirect("/login")
        json_token = check_token(token, pubkey())
        if not json_token:
            # The token isn't valid
            return redirect("/login")
        return f(*args, **kwargs, access_token=json_token)
    return decorated


# Wrapper for when a user _may_ be authenticated
def optional_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token formatting
            # formatting
            return f(*args, **kwargs, access_token=None)
        if not token:
            # Token isn't in the request or the session
            return f(*args, **kwargs, access_token=None)
        json_token = check_token(token, pubkey())
        if not json_token:
            # The token isn't valid
            return f(*args, **kwargs, access_token=None)
        return f(*args, **kwargs, access_token=json_token)
    return decorated


@app.route("/")
@optional_authentication
def root(access_token=None):
    # Go get the pubkey to confirm the token from the server
    if access_token is not None:
        return render_template('logged_in.html', user=access_token['user'], token=get_token())
    else:
        return "<a href='{}'>Login</a> <a href='{}'>Register</a>".format(
            url_for("login"),
            url_for("register")
        )


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        # post, set token in session
        token_resp = requests.get(
            environ['WHOGOESTHERE_URL'] + '/auth_user',
            data={
                'user': request.form['user'],
                'pass': request.form['password']
            }
        )
        if token_resp.status_code != 200:
            # Incorrect username/password
            return redirect("/login")
        token = token_resp.text
        session['access_token'] = token
        response = make_response(redirect("/"))
        return response
    else:
        # Get, serve the form
        return render_template('login.html', form=form)


@app.route("/logout")
@requires_authentication
def logout(access_token=None):
    if not access_token:
        raise AssertionError("No token!")
    try:
        del session['access_token']
    except KeyError:
        pass
    return redirect("/")


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():

        # post, make a user
        make_user_resp = requests.post(
            environ['WHOGOESTHERE_URL'] + "/make_user",
            data={
                'user': request.form['user'],
                'pass': request.form['password']
            }
        )
        if make_user_resp.status_code != 200:
            raise ValueError()
        login()
        return redirect("/")
    else:
        # Get, serve the form
        return render_template('register.html', form=form)


@app.route("/refresh_token")
@requires_authentication
def refresh_token(access_token=None):
    if not access_token:
        raise AssertionError("No token!")

    # We use get_token() here to get the base64 original token
    refresh_token_response = requests.get(
        environ['WHOGOESTHERE_URL'] + "/refresh_token",
        data={"access_token": get_token()}
    )
    if refresh_token_response.status_code != 200:
        raise ValueError()
    return make_response(refresh_token_response.text)


@app.route("/deauth_refresh_token", methods=['GET', 'POST'])
@requires_authentication
def deauth_refresh_token(access_token=None):
    if not access_token:
        raise AssertionError("No token!")

    form = DeauthRefreshTokenForm()
    if form.validate_on_submit():
        del_refresh_token_response = requests.delete(
            environ['WHOGOESTHERE_URL'] + '/refresh_token',
            data={"access_token": get_token(),
                  "refresh_token": request.form['refresh_token']}
        )
        if del_refresh_token_response.status_code != 200:
            raise ValueError()
        return make_response("Deleted!")
    else:
        return render_template('deauth_refresh_token.html', form=form)
