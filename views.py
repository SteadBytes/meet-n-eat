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
def verify_password(username, password):
    user = session.query(User).filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    g.user  # add user to session
    return True


@auth.verify_password
@app.route('/api/v1/users', methods=["GET"])
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


@app.route('/api/v1/login', methods=['POST'])
def user_login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = session.query(User).filter_by(username=username).first()
    if not user.verify_password(password):
        return jsonify({'error': "Incorrect username or password"}), 422

    login_session['username'] = username
    return jsonify({'message': "User successfully logged in", 'user': user.serialize}), 200


@auth.verify_password
@app.route('/api/v1/users', methods=["PUT", 'DELETE'])
def update_delete_user():
    pass


@auth.verify_password
@app.route('/api/v1/users/<int:id>', methods=["GET"])
def get_user(id):
    pass


@app.route('/api/v1/<provider>/login', methods=["POST"])
def login(provider):
    pass


@app.route('/api/v1/<provider>/logout', methods=["POST"])
def logout(provider):
    pass


@auth.verify_password
@app.route('/api/v1/requests', methods=["GET"])
def get_requests():
    pass


@auth.verify_password
@app.route('/api/v1/requests', methods=["POST"])
def make_request():
    pass


@auth.verify_password
@app.route('/api/v1/requests/<int:id>', methods=["GET"])
def get_request(id):
    pass


@auth.verify_password
@app.route('/api/v1/requests/<int:id>', methods=["PUT", "DELETE"])
def update_request(id):
    pass


@auth.verify_password
@app.route('/api/v1/proposals', methods=["GET"])
def get_proposals():
    pass


@auth.verify_password
@app.route('/api/v1/proposals', methods=["POST"])
def make_proposal():
    pass


@auth.verify_password
@app.route('/api/v1/proposals/<int:id>', methods=["GET"])
def get_proposal(id):
    pass


@auth.verify_password
@app.route('/api/v1/proposals/<int:id>', methods=["PUT", "DELETE"])
def update_proposal(id):
    pass


@auth.verify_password
@app.route('/api/v1/dates', methods=["GET"])
def get_dates():
    pass


@auth.verify_password
@app.route('/api/v1/dates', methods=["POST"])
def make_date():
    pass


@auth.verify_password
@app.route('/api/v1/dates/<int:id>', methods=["GET"])
def get_date(id):
    pass


@auth.verify_password
@app.route('/api/v1/dates/<int:id>', methods=["PUT", "DELETE"])
def udpate_date(id):
    pass


if __name__ == '__main__':
    app.secret_key = 'secret_key_very_secret'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
