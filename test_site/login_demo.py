"""
Demo of using a ipseity JWT server for authentication.

# Required env vars
* IPSEITY_URL: The URL of the ipseity server
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
* IPSEITY_PUBKEY: The pubkey of the ipseity server,
    providing it explicitly will prevent periodically retrieving
    it from the remote server
* PUBKEY_CACHE_TIMEOUT: How long, in seconds, before we check
    the ipseity server to refresh the pubkey cache
    (if in use). Defaults to 300 seconds (5 minutes)
"""

from os import environ
from uuid import uuid4
from urllib.parse import urlparse, urljoin
from flask import Flask, request, redirect, make_response, session, \
    render_template, url_for, g
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo
import requests
from pymongo import MongoClient

import flask_jwtlib


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
# flask_jwtlib setup
# =====

# Setup pubkey, either static from env var or retrieved from server
if environ.get("IPSEITY_PUBKEY"):
    flask_jwtlib.set_permanent_pubkey(environ['IPSEITY_PUBKEY'])
else:
    def retrieve_pubkey():
        pubkey_resp = requests.get(environ['IPSEITY_URL'] + "/pubkey")
        if pubkey_resp.status_code != 200:
            raise ValueError("Pubkey couldn't be retrieved!")
        pubkey = pubkey_resp.text
        return pubkey

    flask_jwtlib.retrieve_pubkey = retrieve_pubkey


def get_token():
    """
    Our own get_token() implementation, which also checks the session

    We store the token in the session to prevent the user from having to
    pass their token with every request, or continuously prompt them for
    login credentials

    Note that this function **just** returns the raw token, it doesn't
    perform any validatin what-so-ever.
    """
    # Prioritize tokens on the request itself
    token = flask_jwtlib._DEFAULT_GET_TOKEN()
    if not token:
        token = session.get('access_token', None)
    return token


flask_jwtlib.get_token = get_token


def required_auth_fail_callback():
    try:
        del session['access_token']
    except KeyError:
        pass
    return redirect(url_for("login"))


def optional_auth_fail_callback():
    try:
        del session['access_token']
    except KeyError:
        pass


flask_jwtlib.requires_authentication.no_auth_callback = \
    required_auth_fail_callback


flask_jwtlib.optional_authentication.no_auth_callback = \
    optional_auth_fail_callback


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
@flask_jwtlib.optional_authentication
def root():
    # Go get the pubkey to confirm the token from the server
    if g.authenticated:
        return render_template(
            'logged_in.html',
            user=g.json_token['user'],
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
            environ['IPSEITY_URL'] + '/auth_user',
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
@flask_jwtlib.requires_authentication
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
            environ['IPSEITY_URL'] + "/make_user",
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
@flask_jwtlib.requires_authentication
def refresh_token():
    # Hammering refresh on this page will generate a new
    # refresh token each time - in reality this page
    # should probably generate a new page dynamically
    # with the token on it to redirect to.
    refresh_token_response = requests.get(
        environ['IPSEITY_URL'] + "/refresh_token",
        data={"access_token": g.raw_token}
    )
    if refresh_token_response.status_code != 200:
        raise ValueError()
    return make_response(refresh_token_response.text)


@app.route("/deauth_refresh_token", methods=['GET', 'POST'])
@flask_jwtlib.requires_authentication
def deauth_refresh_token():
    form = DeauthRefreshTokenForm()
    if form.validate_on_submit():
        del_refresh_token_response = requests.delete(
            environ['IPSEITY_URL'] + '/refresh_token',
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
