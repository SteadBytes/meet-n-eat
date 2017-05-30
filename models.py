from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import(
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in range(32))


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String, index=True)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({"id": self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # valid but expired token
            return None
        except BadSignature:
            # token invalid
            return None
        user_id = data['id']
        return user_id

    @property
    def serialize(self):
        return {
            'username': self.username,
            'email': self.email,
            'picture': self.picture,
        }


class Request(Base):
    __tablename__ = 'request'
    id = Column(Integer, primary_key=True)
    meal_type = Column(String)
    location_string = Column(String)
    latitude = Column(String)
    longitude = Column(String)
    meal_time = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'meal_type': self.meal_type,
            'location_string': self.location_string,
            'longitude': self.longitude,
            'latitude': self.latitude,
            'meal_time': self.meal_time,
            'user_id': self.user_id
        }


class Proposal(Base):
    __tablename__ = 'proposal'
    id = Column(Integer, primary_key=True)
    to_user = Column(Integer, ForeignKey('user.id'))
    from_user = Column(Integer, ForeignKey('user.id'))
    user1 = relationship("User", foreign_keys=[to_user])
    user2 = relationship("User", foreign_keys=[from_user])
    request_id = Column(Integer, ForeignKey('request.id'))
    request = relationship(Request)

    @property
    def serialize(self):
        return {
            'to_user': self.to_user,
            'from_user': self.from_user,
        }


class MealDate(Base):
    __tablename__ = 'meal_date'
    id = Column(Integer, primary_key=True)
    user1_id = Column(Integer, ForeignKey('user.id'))
    user2_id = Column(Integer, ForeignKey('user.id'))

    user1 = relationship("User", foreign_keys=[user1_id])
    user2 = relationship("User", foreign_keys=[user2_id])

    restaurant_name = Column(String)
    restaurant_address = Column(String)
    restaurant_picture = Column(String)
    meal_time = Column(String)


engine = create_engine('sqlite:///meet-n-eat.db')


Base.metadata.create_all(engine)
