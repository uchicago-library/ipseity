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
from urllib.parse import urlparse, urljoin
import datetime
from functools import wraps
from flask import Flask, request, redirect, make_response, session, \
    render_template, url_for, g
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, HiddenField
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


# We want to set some defaults per-request on g,
# so that we can use them later while processing requests.
@app.before_request
def set_g_defaults():
    """
    Set the defaults for the authentication variables
    """
    g.authenticated = False
    g.raw_token = None
    g.json_token = None


# =====
# pubkey cache
# =====
# We store the key itself and the last time
# it was retrieved at, so we can keep it fresh
# if we're pulling from the server
pubkey_tuple = None
# If we explicitly set the pubkey never check it from the server
# We stop checks by setting the time we retrieved it in the distant
# future, so it never ends up too long ago.
if environ.get("WHOGOESTHERE_PUBKEY"):
    pubkey_tuple = (environ['WHOGOESTHERE_PUBKEY'],
                    datetime.datetime.max)


def pubkey():
    """
    Returns the public key used for verifying JWTs

    This function includes the machinery for managing the pubkey cache,
    if one wasn't specified via an env var.

    Note this will **never** refresh the key if one was supplied via
    an env var.
    """
    global pubkey_tuple
    cache_timeout = datetime.timedelta(seconds=environ.get("PUBKEY_CACHE_TIMEOUT", 300))
    if not pubkey_tuple or \
            (datetime.datetime.now() - pubkey_tuple[1]) > cache_timeout:
        # Refresh the pubkey tuple
        pubkey_resp = requests.get(environ['WHOGOESTHERE_URL'] + "/pubkey")
        if pubkey_resp.status_code != 200:
            if not pubkey_tuple:
                raise ValueError("Pubkey couldn't be retrieved!")
        pubkey = pubkey_resp.text
        pubkey_tuple = (pubkey, datetime.datetime.now())
    return pubkey_tuple[0]


# =====
# Token functions
# =====


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
        return True
    except jwt.InvalidTokenError:
        return False


def _get_token_from_header():
    """
    https://tools.ietf.org/html/rfc6750#section-2.1
    """
    try:
        auth_header = request.headers['Authorization']
        if not auth_header.startswith("Bearer: "):
            raise ValueError("Malformed auth header")
        return auth_header[8:]
    except KeyError:
        # Auth isn't in the header
        return None


def _get_token_from_form():
    """
    https://tools.ietf.org/html/rfc6750#section-2.2
    """
    try:
        return request.form['access_token']
    except KeyError:
        return None


def _get_token_from_query():
    """
    https://tools.ietf.org/html/rfc6750#section-2.3
    """
    try:
        return request.args['access_token']
    except KeyError:
        return None


def _get_token():
    """
    Get the token from the response
    Expects the response to supply the token in one of the
    three ways specified in RFC 6750
    """
    # https://tools.ietf.org/html/rfc6750#section-2
    tokens = []

    for x in [_get_token_from_header,
              _get_token_from_form,
              _get_token_from_query]:
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
    """
    A wrapper for _get_token() which also checks the session.

    We store the token in the session to prevent the user from having to
    pass their token with every request, or continuously prompt them for
    login credentials

    Note that this function **just** returns the raw token, it doesn't
    perform any validatin what-so-ever.
    """
    token = _get_token()
    if not token:
        token = session.get('access_token', None)
    return token


def get_json_token(verify=True):
    """
    A wrapper for get_token() which decodes the token and returns the JSON

    Verifies the token by default during the operation, but by passing
    the kwarg verify=False you can just get at the json sans verification.
    """
    token = get_token()
    json_token = jwt.decode(
        token,
        pubkey(),
        algorithm="RS256",
        verify=verify
    )
    return json_token


# =====
# Decorators
# =====


# Wrapper for when a user _must_ be authenticated
def requires_authentication(f):
    """
    A decorator for applying to routes where authentication is required.

    If the event a user is not authenticated they will be redirected
    to /login
    """

    def callback():
        try:
            del session['access_token']
        except KeyError:
            pass
        return redirect(url_for("login"))

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token formatting
            return callback()
        if not token:
            # Token isn't in the request or the session
            return callback()
        if not check_token(token, pubkey()):
            # The token isn't valid
            return callback()
        g.authenticated = True
        g.raw_token = get_token()
        g.json_token = get_json_token()
        return f(*args, **kwargs)
    return decorated


# Wrapper for when a user _may_ be authenticated
def optional_authentication(f):

    def callback():
        try:
            del session['access_token']
        except KeyError:
            pass

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token formatting
            # formatting
            callback()
            return f(*args, **kwargs)
        if not token:
            # Token isn't in the request or the session
            callback()
            return f(*args, **kwargs)
        json_token = check_token(token, pubkey())
        if not json_token:
            # The token isn't valid
            callback()
            return f(*args, **kwargs)
        g.authenticated = True
        g.raw_token = get_token()
        g.json_token = get_json_token()
        return f(*args, **kwargs)
    return decorated


# =====
# Forms
# =====

# inspired by http://flask.pocoo.org/snippets/63/
# Note that this never uses request.referrer - if
# pages want the user to get redirect back to them
# they should link to /login?next=$THEIR_URL_HERE
class RedirectForm(FlaskForm):
    """
    A form object which intelligently handles redirects.

    Templates should include the following their form element:
    {{ form.next() or '' }}

    Rendering the original form will pull anything passed via
    form values or the query string and drop it in the hidden field.

    When the POST is sent the value is then checked, and if it passes
    the criteria of is_safe_url the user is redirected to the page.
    """

    next = HiddenField()

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        if self.next.data is None:
            self.next.data = request.values.get("next", '')

    def is_safe_url(self, target):
        """
        Checks if a URL is safe to redirect to
        """
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        if test_url.scheme in ('http', 'https') and \
                ref_url.netloc == test_url.netloc:
            return True
        else:
            return False

    def redirect(self, endpoint='root'):
        if self.next.data is not None and \
                self.is_safe_url(request.form['next']):
            return redirect(request.form['next'])
        else:
            return redirect(url_for(endpoint))


class LoginForm(RedirectForm):
    """
    Form for handling login information
    """
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
    next = HiddenField()


class RegistrationForm(RedirectForm):
    """
    Form for handling registration information
    """
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
    next = HiddenField()


class DeauthRefreshTokenForm(FlaskForm):
    """
    Form for getting the refresh token to deauth
    """
    refresh_token = StringField(
        'refresh_token',
        validators=[
            DataRequired()
        ]
    )


# =====
# Routes
# =====

@app.route("/")
@optional_authentication
def root():
    # Go get the pubkey to confirm the token from the server
    if g.authenticated:
        return render_template(
            'logged_in.html',
            user=get_json_token()['user'],
            token=g.json_token
        )
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
            return redirect(url_for("login"))
        token = token_resp.text
        session['access_token'] = token
        return form.redirect('root')
    else:
        # Get, serve the form
        return render_template(
            'login.html',
            form=form,
            register_url=url_for('register')
        )


@app.route("/logout")
@requires_authentication
def logout():
    g.authenticated = False
    g.raw_token = None
    g.json_token = None
    try:
        del session['access_token']
    except KeyError:
        pass
    return redirect(url_for("root"))


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
        return redirect(url_for("root"))
    else:
        # Get, serve the form
        return render_template(
            'register.html',
            form=form,
            login_url=url_for('login')
        )


@app.route("/refresh_token")
@requires_authentication
def refresh_token():
    # Hammering refresh on this page will generate a new
    # refresh token each time - in reality this page
    # should probably generate a new page dynamically
    # with the token on it to redirect to.
    refresh_token_response = requests.get(
        environ['WHOGOESTHERE_URL'] + "/refresh_token",
        data={"access_token": g.raw_token}
    )
    if refresh_token_response.status_code != 200:
        raise ValueError()
    return make_response(refresh_token_response.text)


@app.route("/deauth_refresh_token", methods=['GET', 'POST'])
@requires_authentication
def deauth_refresh_token():
    form = DeauthRefreshTokenForm()
    if form.validate_on_submit():
        del_refresh_token_response = requests.delete(
            environ['WHOGOESTHERE_URL'] + '/refresh_token',
            data={"access_token": g.raw_token,
                  "refresh_token": request.form['refresh_token']}
        )
        if del_refresh_token_response.status_code != 200:
            raise ValueError()
        return redirect(url_for("root"))
    else:
        return render_template(
            'deauth_refresh_token.html',
            form=form
        )
