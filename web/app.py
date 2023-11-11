from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy as np
import requests

from keras.applications import InceptionV3
from keras.applications.inception_v3 import preprocess_input
from keras.applications import imagenet_utils
from tensorflow.keras.preprocessing.image import img_to_array
from PIL import Image
from io import BytesIO

#Load the pretrained model
pretrained_model = InceptionV3(weights="imagenet")

app = Flask(__name__)
api = Api(app)

#Initialize MongoClient
client = MongoClient("mongodb://db:27017")

#create a new db and collection
db = client.ImageRocognition
users = db["Users"]

def user_exists(username):
    if users.count_documents({"Username":username}) == 0:
        return False
    else:
        return True


class Register(Resource):
    def post(self):
        #get postted data
        posted_data = request.get_json()

        #Get user name and password
        username = posted_data["username"]
        password = posted_data["password"]

        #Check if user already exists
        if user_exists(username):
            return jsonify({
                "status": 301,
                "message":"Invalid username, user already exists"
            })

        #If user is new, hash password
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #Store the new user in the database
        users.insert_one({
            "Username":username,
            "Password":hashed_pw,
            "Tokens":4
        })

        #Return success
        ret_json = {
            "status": 200,
            "message": "You have successfully registered on the Api - Have 4 tokens"
        }
        return jsonify(ret_json)

def verify_pw(username, password):
    if not user_exists(username):
        return False

    hashed_pw = users.find({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def generate_return_dictionary(status, msg):
    ret_json = {
        "status": status,
        "msg": msg
    }
    return ret_json

def verify_credentials(username, password):
    if not user_exists(username):
        return generate_return_dictionary(301, "Invalid Username"), True

    correct_pw = verify_pw(username, password)

    if not correct_pw:
        return generate_return_dictionary(302, "Incorrect Password"), True

    return None, False



class Classify(Resource):
    def post(self):

        #Get posted data
        posted_data = request.get_json()

        #We get credentials and url
        username = posted_data["username"]
        password = posted_data["password"]
        url = posted_data["url"]
        #verify credentials
        ret_json, error = verify_credentials(username, password)
        if error:
            return jsonify(ret_json)


        #check if user has tokens available
        tokens = users.find({
            "Username":username
        })[0]["Tokens"]

        if tokens <= 0:
            return jsonify(generate_return_dictionary(303, "Not enough tokens"))
        #Classify the image

        if not url:
            return jsonify(({"error":"No URL provided"}), 400)

        #load image from URL
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))

        #preprocess the image
        img = img.resize((299,299))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)
        #Make prediction
        prediction = pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top=5)


        #return classification response
        ret_json = {}
        for pred in actual_prediction[0]:
            ret_json[pred[1]] = float(pred[2]*100)


        #reduce tokens
        users.update_one({
            "Username":username
            },{
                "$set":{
                "Tokens": tokens-1
                }
        })
        return jsonify(ret_json)


class Refill(Resource):
    def post(self):
        #Get posted data
        posted_data = request.get_json()

        #We get credentials
        username = posted_data["username"]
        password = posted_data["admin_pw"]
        amount = posted_data["amount"]

        #check if user exists
        if not user_exists(username):
            return jsonify(generate_return_dictionary(301, "Invalid Username"))

        #Check admin password

        correct_pw = "abc123"

        if not password == correct_pw:
            return jsonify(generate_return_dictionary(302, "Incorrect Admin Password"))



        #Update token respond
        users.update_one({
            "Username":username
            },{
                "$set":{
                "Tokens": amount
                }
        })
        return jsonify(generate_return_dictionary(200, "Refilled"))


api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__== '__main__':
    app.run(host='0.0.0.0')
