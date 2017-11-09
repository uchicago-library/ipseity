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
from flask import Flask, request, redirect, session, \
    url_for, g, flash
from json import dumps
# We're going to wrap render_template() to avoid providing the same
# information over and over again to each call
from flask import render_template as _render_template
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
    flask_jwtlib.set_permanent_signing_key(environ['IPSEITY_PUBKEY'])
else:
    def retrieve_pubkey():
        pubkey_resp = requests.get(environ['IPSEITY_URL'] + "/pubkey")
        if pubkey_resp.status_code != 200:
            raise ValueError("Pubkey couldn't be retrieved!")
        pubkey = pubkey_resp.text
        return pubkey

    flask_jwtlib.retrieve_signing_key = retrieve_pubkey


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


flask_jwtlib.requires_authentication_failure_callback = \
    required_auth_fail_callback


flask_jwtlib.optional_authentication_failure_callback = \
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
        'User Name',
        validators=[
            DataRequired(),
            Length(min=3)
        ]
    )
    # Password field can be completely blank, for token logins
    password = PasswordField(
        'Password',
        validators=[]
    )
    next = HiddenField()


class RegistrationForm(RedirectForm):
    """
    Form for handling registration information
    """
    user = StringField(
        'User Name',
        validators=[
            DataRequired(),
            Length(min=3)
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=3),
            EqualTo('confirm', message='Passwords must match')
        ]
    )
    confirm = PasswordField(
        'Repeat Password'
    )
    next = HiddenField()


class ChangePasswordForm(FlaskForm):
    """
    Form for changing passwords
    """
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=3),
            EqualTo('confirm', message='Passwords must match')
        ]
    )
    confirm = PasswordField(
        'Repeat Password'
    )


class DeauthRefreshTokenForm(FlaskForm):
    """
    Form for getting the refresh token to deauth
    """
    refresh_token = StringField(
        'Refresh Token',
        validators=[
            DataRequired()
        ]
    )


class DeleteMeForm(FlaskForm):
    pass


# =====
# Utility functions
# =====
def render_template(*args, **kwargs):
    return _render_template(
        *args,
        external_ipseity_url=environ.get('EXTERNAL_IPSEITY_URL'),
        json_token=g.get('json_token'),
        raw_token=g.get('raw_token'),
        **kwargs
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
            pretty_json_token=dumps(g.json_token, indent=2)
        )
    else:
        return redirect(url_for("login"))


# An example of using the optional authentication
# decorator in order to prevent an authenticated
# user from accessing a resource
@app.route("/login", methods=['GET', 'POST'])
@flask_jwtlib.optional_authentication
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
            flash("Incorrect username/password", 'alert-danger')
            return redirect(url_for("login", next=request.form['next']))
        token = token_resp.text
        session['access_token'] = token
        flash("You've been logged in", 'alert-success')
        return form.redirect('root')
    else:
        # Get, serve the form
        return render_template(
            'login.html',
            title="Log In",
            form=form
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
    flash("You've been logged out!", 'alert-success')
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
            flash("That username is already taken!", 'alert-danger')
            return redirect(url_for("register"))
        login()
        return redirect(url_for("root"))
    else:
        # Get, serve the form
        return render_template(
            'register.html',
            title="Register",
            form=form
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
        flash("There was a problem generating your token!", 'alert-danger')
        redirect(url_for("root"))
    return render_template(
        'display_refresh_token.html',
        refresh_token=refresh_token_response.text
    )


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
            flash("There was a problem deauthenticating your token!", 'alert-danger')
            redirect(url_for("root"))
        flash("Refresh token deauthenticated!", 'alert-success')
        return redirect(url_for("root"))
    else:
        return render_template(
            'deauth_refresh_token.html',
            title='Deauthenticate a refresh token',
            form=form
        )


@app.route("/delete_me", methods=['GET', 'POST'])
@flask_jwtlib.requires_authentication
def delete_me():
    form = DeleteMeForm()
    if form.validate_on_submit():
        del_response = requests.delete(
            environ['IPSEITY_URL'] + '/del_user',
            data={"access_token": g.raw_token}
        )
        if del_response.status_code != 200:
            flash("There was a problem deleting your account!", "alert-danger")
        try:
            del session['access_token']
        except KeyError:
            pass
        flash("Account deleted!", "alert-info")
        return redirect(url_for("root"))
    else:
        if g.json_token['authentication_method'] != 'password':
            flash("Account deletion requires a password based token", "alert-info")
            return redirect("/login?next=/delete_me")
        return render_template(
            'delete_me.html',
            title='Delete Your Account',
            form=form
        )


@app.route("/change_pass", methods=['GET', 'POST'])
@flask_jwtlib.requires_authentication
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        change_pass_response = requests.post(
            environ['IPSEITY_URL'] + "/change_pass",
            data={"access_token": g.raw_token,
                  "new_pass": request.form['password']}
        )
        if change_pass_response.status_code != 200:
            flash("There was a problem changing your password!", "alert-danger")
        else:
            flash("Your password has been updated!", "alert-info")
        return redirect(url_for("root"))
    else:
        if g.json_token['authentication_method'] != 'password':
            flash("Password changes require a password based token", "alert-info")
            return redirect("/login?next=/change_pass")
        return render_template(
            'change_pass.html',
            title='Change Password',
            form=form
        )
