
import json
import httplib2

import sys
import codecs

foursquare_client_id = json.loads(
    open('secrets/foursquare_secrets.json', 'r').read())['client_id']
foursquare_client_secret = json.loads(
    open('secrets/foursquare_secrets.json', 'r').read())['client_secret']
google_api_key = json.loads(
    open('secrets/google_geocode.json', 'r').read())['geocoding']['key']


def get_geocode_location(input_string):
    # Replace spaces with '+' for appending to URL string
    location_string = input_string.replace(" ", "+")
    url = ("https://maps.googleapis.com/maps/api/geocode/json?address=%s&key=%s" %
           (location_string, google_api_key))
    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    result = json.loads(content.decode())
    # print("Response header: %s \n \n" % response)

    latitude = result['results'][0]['geometry']['location']['lat']
    longitude = result['results'][0]['geometry']['location']['lng']

    return (latitude, longitude)


def find_a_restaurant(meal_type, location_string):
    # Geocode location_string to get ll
    latitude, longitude = get_geocode_location(location_string)
    ll = str(latitude) + ',' + str(longitude)
    # call foursquare api venues/search endpoint, params:
    # intent=browse, query=meal_type, ll=geocode_location, v=20170525
    # client_id, client_secret

    url = ("https://api.foursquare.com/v2/venues/search?ll=%s&client_id=%s&client_secret=%s&v=20170525&intent=browse&query=%s&radius=1000" %
           (ll, foursquare_client_id, foursquare_client_secret, meal_type))
    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    # print("Response header: " + response.decode())
    result = json.loads(content.decode())

    # get venue_id
    # Parse JSON response to return first restaurant
    if result['response']['venues']:
        restaurant_info = result['response']['venues'][0]
        venue_id = restaurant_info['id']

        restaurant_name = restaurant_info['name']
        address = restaurant_info['location']['address']

        # Retrieve image of restaurant, if none available use 'default.jpg'
        # https://api.foursquare.com/v2/venues/VENUE_ID/photos
        url = ("https://api.foursquare.com/v2/venues/%s/photos?client_id=%s&client_secret=%s&v=20170525") % (
            venue_id, foursquare_client_id, foursquare_client_secret)
        h = httplib2.Http()
        response, content = h.request(url, 'GET')
        result = json.loads(content.decode())
        if result['response']['photos']['count'] > 0:

            image_url = result['response']['photos']['items'][0]['source']['url']
        else:
            image_url = "http://pixabay.com/get/8926af5eb597ca51ca4c/1433440765/cheeseburger-34314_1280.png?direct"

        # print result to terminal
        # print("Restaurant name: " + str(restaurant_name))
        # print("Address: " + str(address))
        # print("Image: " + str(image_url))
        # return dict (restaurant_name, address, image)
        return{'name': restaurant_name, 'address': address, 'image_url': image_url}
    else:
        return "No restaurants found"
