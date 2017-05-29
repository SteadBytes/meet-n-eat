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


@app.route('/api/v1/<str:provider>/login', methods=["POST"])
def login(provider):
    pass


@app.route('/api/v1/<str:provider>/logout', methods=["POST"])
def logout(provider):
    pass


@app.route('/api/v1/users', methods=["GET"])
def get_users():
    pass


@app.route('/api/v1/users', methods=["POST"])
def make_user():
    pass


@app.route('/api/v1/users', methods=["PUT", 'DELETE'])
def update_delete_user():
    pass


@app.route('/api/v1/users/<int:id>', methods=["GET"])
def get_user(id):
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
