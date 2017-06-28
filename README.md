# Meet N' Eat
![Part of the Udacity Full-Stack Web Development Nanodegree](https://img.shields.io/badge/Udacity-Full--Stack%20Web%20Developer%20Nanodegree-02b3e4.svg)
----------------------------
Meet N' Eat is a social application for meeting people based on their food interests

## Requirements
* Python3
* Flask
* Flask-HTTPauth
* SQLAlchemy
* itsdangerous
* Redis
* oauth
* passlib

## Usage

### Setup external APIs
1. Navigate to `secrets` directory
2. Set up a new Google project [here](https://console.developers.google.com/).
3. Set up Oauth 2 and Google Maps Geocode API under the google API manager.
4. Download the **Oauth2 client id JSON** from the credentials section and replace the `client_secrets.json` file with it.
5. Copy the API key for Geocoding from the same page and place into `google_geocode.json`
6. Create a new Foursquare app [here](https://developer.foursquare.com/)
7. Copy the `CLIENT_ID` and `CLIENT_SECRET` into `foursquare_secrets.json`

### Run Meet N' Eat API
1. Create database:
  * `$ python3 models.py`
2. Optional - populate database with test data:
  * `python3 tests.py`
3. Make sure Redis server is running for rate limiting
  * `$ redis-server`
3. API can be run with:
  * `$ python3 views.py`
4. API is now accessible on `localhost:5000`

### Udacity Vagrant VM
Allows for easy usage with same system configuration used during development:
1. Ensure [Vagrant](https://www.vagrantup.com/), [Virtual Box](https://www.virtualbox.org/) and [Python](https://www.python.org/) are installed on your machine.
2. Clone the Udacity [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm)
3. [Clone](https://github.com/SteadBytes/meet-n-eat.git) or [download](https://github.com/SteadBytes/meet-n-eat/archive/master.zip) this repo into the `/vagrant` directory
4. Launch the VM:
  * `vagrant$ vagrant up`
5. SSH into the VM:
  * On Mac/Linux `vagrant$ vagrant ssh`
    * Gives SSH connection details on windows
  * Windows use Putty or similar SSH client
6. In the VM navigate to the `/vagrant/udacity-fsnd-meet-n-eat` directory:
  * `$ cd /vagrant/udacity-fsnd-meet-n-eat`
7. Usage is the same as in the [Usage section](#usage)
