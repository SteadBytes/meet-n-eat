from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import User
engine = create_engine('sqlite:///meet-n-eat.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()


def populate_users():
    for i in range(0, 10):
        username = "user%s" % str(i)
        email = "%s@test.com" % username
        user = User(username=username, email=email)
        user.hash_password("securepassword%s" % str(i))
        user.picture = "%s.jpg" % username
        session.add(user)
        session.commit()
        print("%s created successfully" % username)


populate_users()
