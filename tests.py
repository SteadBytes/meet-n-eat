from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import random
from findarestaurant import get_geocode_location, find_a_restaurant
from models import User, Request, Proposal, MealDate
engine = create_engine('sqlite:///meet-n-eat.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()


def populate_users():
    for i in range(1, 11):
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
              "Noodles", "Vegan", "Asian", "Japanese",
              "Tacos", "Coffee", "Burritos", "Salad", "Steak"]

location_strings = ["Colchester, Essex", "Jakarta, Indonesia",
                    "Tokyo, Japan", "Sydney Australia", "Los Angeles, California"]
user_ids = list(range(1, 11))


def populate_requests():
    for i in range(1, 11):
        meal_type = random.choice(meal_types)
        location_string = random.choice(location_strings)
        latitude, longitude = get_geocode_location(location_string)
        meal_time = random.choice(meal_times)
        user_id = i
        request = Request(meal_type=meal_type, location_string=location_string,
                          latitude=latitude, longitude=longitude, meal_time=meal_time, user_id=user_id)
        session.add(request)
        print("Request for %s at %s in %s added successfully" %
              (meal_type, meal_time, location_string))
    session.commit()


def populate_proposals():
    for i in range(1, 11):
        from_user = random.choice(user_ids)
        to_user = random.choice(user_ids)
        if to_user == from_user:
            to_user -= 1
        request_id = i
        proposal = Proposal(from_user=from_user,
                            to_user=to_user, request_id=request_id)
        session.add(proposal)
        print("Proposal from %s to %s added successfully" %
              (from_user, to_user))
    session.commit()


def populate_dates():
    proposals = session.query(Proposal).all()
    for proposal in proposals:
        r = session.query(Request).filter_by(
            id=proposal.request_id).first()
        user1_id = proposal.to_user
        user2_id = proposal.from_user
        meal_time = r.meal_time
        try:
            restaurant_info = find_a_restaurant(r.meal_type, r.location_string)
            if type(restaurant_info) == dict:
                restaurant_name = restaurant_info['name']
                restaurant_address = restaurant_info['address']
                restaurant_picture = restaurant_info['image_url']
        except Exception as e:
            print(e)

        date = MealDate(user1_id=user1_id, user2_id=user2_id, restaurant_name=restaurant_name,
                        restaurant_address=restaurant_address, restaurant_picture=restaurant_picture, meal_time=meal_time)

        session.add(date)

    session.commit()


# populate_users()
# populate_requests()
# populate_proposals()
populate_dates()
