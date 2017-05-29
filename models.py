from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import(
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String, index=true)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


class Request(Base):
    __tablename__ = 'base'
    id = Column(Integer, primary_key=True)
    meal_type = Column(String)
    location_string = Column(String)
    latitude = Column(string)
    longitude = Column(String)
    meal_time = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


class Proposal(Base):
    __tablename__ = 'proposal'
    id = Column(Integer, primary_key=True)
    to_user = Column(Integer, ForeignKey('user.id'))
    from_user = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    request_id = Column(Integer, ForeignKey('request.id'))
    request = relationship(Request)


class MealDate(Base):
    __tablename__ = 'meal_date'
    id = Column(Integer, primary_key=True)
    user_1 = Column(Integer, ForeignKey('user.id'))
    user_2 = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    restaurant_name = Column(String)
    restaurant_address = Column(String)
    restaurant_picture = Column(String)
    meal_time = Column(String)


engine = create_engine('sqlite:///meet-n-eat.db')


Base.metadata.create_all(engine)
