from os import environ
from uuid import uuid4
import datetime
from functools import wraps
from flask import Flask, request, redirect, make_response, session, \
    render_template, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import requests
import jwt

app = Flask(__name__)
# We have to set a secret key, so we can
# use sessions to store the token after
# the user logs in
app.secret_key = uuid4().hex

pubkey_tuple = None

# If we explicitly set the pubkey never check it from the server
if environ.get("WHOGOESTHERE_PUBKEY"):
    pubkey_tuple = (environ['WHOGOESTHERE_PUBKEY'], datetime.datetime.max)


class UserPassForm(FlaskForm):
    user = StringField('user', validators=[DataRequired()])
    password = PasswordField('pass', validators=[DataRequired()])


def check_token(token, pubkey):
    """
    Check the token
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


def get_token():
    """
    Get the token from the response
    Expects the token to supply the token in one of the
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


# Wrapper for when a user _must_ be authenticated
def requires_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token
            # formatting - redirect to login
            return redirect("/login")
        if not token:
            token = session.get("access_token")
        if not token:
            # Token isn't in the request or the session
            # redirect to login
            return redirect("/login")
        # Keep the pubkey fresh if we're pulling it from the server,
        # if it was manually specified use that one.
        global pubkey_tuple
        if not pubkey_tuple or \
                (datetime.datetime.now() - pubkey_tuple[1]) > datetime.timedelta(seconds=300):
            # Refresh the pubkey tuple
            pubkey_resp = requests.get(environ['WHOGOESTHERE_URL'] + "/pubkey")
            if pubkey_resp.status_code != 200:
                if not pubkey_tuple:
                    raise ValueError("Pubkey couldn't be retrieved!")
            pubkey = pubkey_resp.text
            pubkey_tuple = (pubkey, datetime.datetime.now())
        json_token = check_token(token, pubkey_tuple[0])
        if not json_token:
            # The token isn't valid - redirect to login
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
            # Something is wrong with the token
            return f(*args, **kwargs, access_token=None)
        if not token:
            token = session.get("access_token")
        if not token:
            # Token isn't in the request or the session
            return f(*args, **kwargs, access_token=None)
        # Keep the pubkey fresh if we're pulling it from the server,
        # if it was manually specified use that one.
        global pubkey_tuple
        if not pubkey_tuple or \
                (datetime.datetime.now() - pubkey_tuple[1]) > datetime.timedelta(seconds=300):
            # Refresh the pubkey tuple
            pubkey_resp = requests.get(environ['WHOGOESTHERE_URL'] + "/pubkey")
            if pubkey_resp.status_code != 200:
                if not pubkey_tuple:
                    raise ValueError("Pubkey couldn't be retrieved!")
            pubkey = pubkey_resp.text
            pubkey_tuple = (pubkey, datetime.datetime.now())
        json_token = check_token(token, pubkey_tuple[0])
        if not json_token:
            return f(*args, **kwargs, access_token=None)
        return f(*args, **kwargs, access_token=json_token)
    return decorated


@app.route("/")
@optional_authentication
def root(access_token=None):
    # Go get the pubkey to confirm the token from the server
    if access_token is not None:
        return "<p>Hello {}!</p><a href='{}'>Logout</a>".format(
            access_token['user'],
            url_for("logout")
        )
    else:
        return "<a href='{}'>Login</a> <a href='{}'>Register</a>".format(
            url_for("login"),
            url_for("register")
        )


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = UserPassForm()
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
            raise ValueError("Non 200 response")
        token = token_resp.text
        response = make_response(redirect("/"))
        session['access_token'] = token
        return response
    else:
        # Get, serve the form
        return render_template('login.html', form=form)


@app.route("/logout")
@requires_authentication
def logout(access_token=None):
    try:
        del session['access_token']
    except KeyError:
        pass
    return redirect("/")


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = UserPassForm()
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
