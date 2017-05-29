from models import Base, User, Request, Proposal, MealDate
from flask import Flask, jsonify, request, url_for, abort, g
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from functools import update_wrapper
import time
import json
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests
from redis import Redis

redis = Redis()
auth = HTTPBasicAuth()
engine = create_engine('sqlite:///meet-n-eat.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


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
    return True


@app.route('/api/v1/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/api/v1/login', methods=['POST'])
def user_login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = session.query(User).filter_by(username=username).first()
    if not user.verify_password(password):
        return jsonify({'error': "Incorrect username or password"}), 422

    login_session['username'] = username
    return jsonify({'message': "User successfully logged in", 'user': user.serialize}), 200


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
def get_user(id):
    pass


@app.route('/api/v1/<provider>/login', methods=["POST"])
def login(provider):
    pass


@app.route('/api/v1/<provider>/logout', methods=["POST"])
def logout(provider):
    pass


@app.route('/api/v1/requests', methods=["GET"])
def get_requests():
    pass


@app.route('/api/v1/requests', methods=["POST"])
def make_request():
    pass


@app.route('/api/v1/requests/<int:id>', methods=["GET"])
def get_request(id):
    pass


@app.route('/api/v1/requests/<int:id>', methods=["PUT", "DELETE"])
def update_request(id):
    pass


@app.route('/api/v1/proposals', methods=["GET"])
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
