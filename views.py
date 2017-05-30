from models import Base, User, Request, Proposal, MealDate
from flask import Flask, render_template, jsonify, request, url_for, abort, g
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from functools import update_wrapper
from findarestaurant import find_a_restaurant, get_geocode_location
import time
import json
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests
import random
import string
from redis import Redis

redis = Redis()
auth = HTTPBasicAuth()
engine = create_engine('sqlite:///meet-n-eat.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']


def create_user(login_session):
    newUser = User(username=login_session.get('username'),
                   email=login_session.get('email'), picture=login_session.get('picture'))
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session.get('email')).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user.serialize


def get_user_id(email):
    try:
        user = session.query(User).filter_by(
            email=login_session.get('email')).one()
        return user.id
    except:
        return None


def user_logged_in(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        else:
            return func(*args, **kwargs)
    return wrapper

# handlers


@auth.verify_password
def verify_password(username_or_token, password):
    user_id = User.verify_auth_token(username_or_token)
    # verify_auth_token returns None if not token based login
    # password is then ignored
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user  # add user to session
    print(user.username)
    return True


@app.route('/api/v1/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(6000)
    return jsonify({'token': token.decode('ascii')})


@app.route('/login')
def show_login():
    # Create CSRF token
    # Store in session for validation
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html.j2', STATE=state)


@app.route('/api/v1/login', methods=['POST'])
def user_login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = session.query(User).filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return jsonify({'error': "Incorrect username or password"}), 422

    login_session['username'] = username
    token = user.generate_auth_token(6000)
    return jsonify({'message': "User successfully logged in", 'user': user.serialize, "token": token.decode('ascii')}), 200


@app.route('/api/v1/logout', methods=['POST'])
@auth.login_required
def user_logout():
    if login_session.get('username') == None:
        return jsonify({'error': "No user currently logged in"}), 400
    del login_session['username']
    return jsonify({'message': "User successfully logged out"}), 200


@app.route('/api/v1/users', methods=["GET"])
@auth.login_required
def get_users():
    users = session.query(User).all()
    return jsonify(Users=[i.serialize for i in users])


@app.route('/api/v1/users', methods=["POST"])
def make_user():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    picture = request.json.get('picture')
    if username is None or password is None:
        abort(400)  # missing args
    if session.query(User).filter_by(username=username).first() is not None:
        abort(400)  # user exists
    user = User(username=username, email=email, picture=picture)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'message': 'successful user registration', 'user': user.serialize}), 200


@app.route('/api/v1/users', methods=["PUT", 'DELETE'])
@auth.login_required
def update_delete_user():
    if request.method == 'PUT':
        username = request.json.get('username')
        password = request.json.get('password')
        email = request.json.get('email')
        picture = request.json.get('picture')
        user = g.user
        user.username = username
        user.hash_password(password)
        user.email = email
        user.picture = picture
        session.add(user)
        session.commit()
        g.user = user
        return jsonify({"message": "User successfully updated", "user": user.serialize})
    if request.method == 'DELETE':
        session.delete(g.user)
        session.commit()
    return jsonify({"message": "User successfully deleted"})


@app.route('/api/v1/users/<int:id>', methods=["GET"])
@auth.login_required
def get_user(id):
    try:
        user = session.query(User).filter_by(id=id).one()
    except:
        return jsonify({"error": "No user for given id"}), 404

    if user:
        return jsonify(User=user.serialize)


@app.route('/api/v1/<provider>/login', methods=["POST"])
def login(provider):
    if provider == "google":
        return gconnect()


@app.route('/gconnect', methods=["POST"])
def g_connect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-type'] = 'application/json'
        return response  # no more server side validation if token mismatch

    code = request.data  # one-time code to exchange for credentials object
    try:
        # upgrade authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)  # initiate exchange
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the auth code.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # Check validity of access token
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode())
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-type'] = 'application/json'
    # Verify access token is used for intended use
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token user ID doesn't match given user ID"), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # verify access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token client ID doesn't match app client ID"), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # Check to see if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected'), 200)
        response.headers['Content-type'] = 'application/json'

    # Store access token in the session for use
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    # Store desired info in session
    login_session['provider'] = 'google'
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # if user doesnt exist -> make new user
    user_id = get_user_id(login_session.get('email'))
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_info'] = get_user_info(user_id)

    return jsonify(data)


@app.route('/gdisconnect')
def g_disconnect():
    # revoke a current users token and reset their login session
    credentials = login_session.get('credentials')
    # only disconnect a connected user
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # GET request to google token revoke url
    # access_token = credentials.access_token
    access_token = credentials
    url = "https://accounts.google.com/o/oauth2/revoke?token=%s" % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # reset users session on successful request
    if result['status'] == '200':

        response = make_response(json.dumps(
            'User successfully disconnected.'), 200)
        response.headers['Content-type'] = 'application/json'
        return response
    else:
        # Invalid token error 400
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-type'] = 'application/json'
        return response


@app.route('/api/v1/<provider>/logout', methods=["POST"])
@auth.login_required
def logout(provider):
    if provider == 'google':
        gdisconnect()
        del login_session['gplus_id']
        del login_session['credentials']

    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']
    flash("You have successfully been logged out.")
    return redirect(url_for('show_login'))


@app.route('/api/v1/requests', methods=["GET"])
@auth.login_required
def get_requests():
    requests = session.query(Request).all()
    return jsonify(Requests=[i.serialize for i in requests])


@app.route('/api/v1/requests', methods=["POST"])
@auth.login_required
def make_request():
    user_id = request.json.get('user_id')
    meal_type = request.json.get('meal_type')
    location_string = request.json.get('location_string')
    meal_time = request.json.get('meal_time')
    lat, lng = get_geocode_location(location_string)
    newRequest = Request(user_id=user_id, meal_type=meal_type,
                         location_string=location_string, latitude=lat,
                         longitude=lng, meal_time=meal_time)
    session.add(newRequest)
    session.commit()
    return jsonify({"message": "New MealDate request successful", "request": newRequest.serialize})


@app.route('/api/v1/requests/<int:id>', methods=["GET"])
@auth.login_required
def get_request(id):
    try:
        r = session.query(Request).filter_by(id=id).one()
    except:
        return jsonify({"error": "No request found for given id"}), 404
    return jsonify(Request=r.serialize)


@app.route('/api/v1/requests/<int:id>', methods=["PUT", "DELETE"])
@auth.login_required
def update_request(id):
    try:
        r = session.query(Request).filter_by(id=id).one()
    except:
        return jsonify({"error": "No request found for given id"})
    user = g.user
    print(r.user_id)
    print(user.id)
    if user.id != r.user_id:
        abort(401)
    if request.method == "PUT":
        if not request.json:
            abort(400)
        user_id = request.json.get('user_id')
        meal_type = request.json.get('meal_type')
        location_string = request.json.get('location_string')
        meal_time = request.json.get('meal_time')
        lat, lng = get_geocode_location(location_string)
        r.meal_type = meal_type
        r.location_string = location_string
        r.meal_time = meal_time
        r.latitude = lat
        r.longitude = lng
        session.add(r)
        session.commit()
        return jsonify({"message": "Request id=%s updated successfully" % id, "request": r.serialize})
    if request.method == "DELETE":
        session.delete(r)
        session.commit()
        return jsonify({"message": "Request id=%s deleted successfully" % id})


@app.route('/api/v1/proposals', methods=["GET"])
@auth.login_required
def get_proposals():
    pass


@app.route('/api/v1/proposals', methods=["POST"])
def make_proposal():
    pass


@app.route('/api/v1/proposals/<int:id>', methods=["GET"])
def get_proposal(id):
    pass


@app.route('/api/v1/proposals/<int:id>', methods=["PUT", "DELETE"])
def update_proposal(id):
    pass


@app.route('/api/v1/dates', methods=["GET"])
def get_dates():
    pass


@app.route('/api/v1/dates', methods=["POST"])
def make_date():
    pass


@app.route('/api/v1/dates/<int:id>', methods=["GET"])
def get_date(id):
    pass


@app.route('/api/v1/dates/<int:id>', methods=["PUT", "DELETE"])
def udpate_date(id):
    pass


if __name__ == '__main__':
    app.secret_key = 'secret_key_very_secret'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
