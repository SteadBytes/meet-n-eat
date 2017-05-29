from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import random
from models import User, Request
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

        print("%s created successfully" % username)
    session.commit()


meal_times = ["Breakfast", "Brunch", "Lunch",
              "Afternoon Tea", "Dinner", "Supper"]
meal_types = ["Pizza", "Sushi", "Italian", "French",
              "Noodles", "Vegan", "Asian", "Japanese"]


def populate_requests():
    for i in range(0, 10):
        meal_type = random.choice(meal_types)
        location_string = "Colchester, Essex"
        latitude = "51.895927"
        longitude = "0.8918740000000001"
        meal_time = random.choice(meal_times)
        user_id = random.randint(1, 10)
        request = Request(meal_type=meal_type, location_string=location_string,
                          latitude=latitude, longitude=longitude, meal_time=meal_time, user_id=user_id)
        session.add(request)
    session.commit()


populate_requests()
