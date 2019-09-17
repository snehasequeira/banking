from flask import Flask,request,jsonify
from flask_restful import Api,Resource
from pymongo import MongoClient
import bcrypt
import os

app = Flask(__name__)
api=Api(app)
client = MongoClient(os.getenv("MONGOURL")) #host uri
db = client.admin
db.authenticate(name=os.getenv("MONGO_USERNAME"),password=os.getenv("MONGO_PASSWORD"))
col=db["banking"]


def userexists(username):
    if col.find({"username":username}).count()==0:
        return False
    else:
        return True

if not userexists("bank"):
    col.insert({
        "username": "bank",
        "deposit": 0
    })
def returnValue(status,message):
    retVal={
        "status":status,
        "message":message
    }

    return retVal
def verifyuser(username,password):
    # invalid username
    if col.find({"username":username}).count()==0:
        return returnValue(301,"user is invalid"),True
    # invalid password
    hash_pass=col.find({"username":username})[0]["password"]
    if not bcrypt.hashpw(password.encode("UTF8"),hash_pass)==hash_pass:
        return returnValue(301, "password is invalid"), True
    else:
        return returnValue(200,"valid user"),False

def accountBalance(username):
    amount=col.find({"username":username})[0]["deposit"]
    return amount

def debtBalance(username):
    debt=col.find({"username":username})[0]["debt"]
    return debt

class registration(Resource):
    def post(self):
        enteredValue=request.get_json()
        username=enteredValue["username"]
        password=enteredValue["password"]
        hash_pwd=bcrypt.hashpw(password.encode("UTF8"),bcrypt.gensalt())
        if userexists(username):
            return jsonify(returnValue(301,"the user already exists"))

        col.insert(
            {
                "username":username,
                "password":hash_pwd,
                "deposit":0,
                "debt":0
            }
        )
        return jsonify(returnValue(200,"successfully registered"))

class deposit(Resource):
    def post(self):
        enteredVal=request.get_json()
        username=enteredVal["username"]
        password=enteredVal["password"]
        deposit=enteredVal["amount"]

        json,error=verifyuser(username,password)
        if error:
            return jsonify(json)
        if deposit<=0:
            return jsonify(returnValue(302,"the entered amount is invalid"))
        balance=accountBalance(username)
        col.update({"username":username},{"$set":
                                              {
                                                  "deposit":balance+deposit
                                              }
                                          })
        return jsonify(returnValue(200,"deposit successful"))

class transfer(Resource):
    def post(self):
        enteredVal = request.get_json()
        username = enteredVal["username"]
        password = enteredVal["password"]
        transfer= enteredVal["amount"]
        to=enteredVal["to"]
        json,error = verifyuser(username, password)
        if error:
            return jsonify(json)
        if transfer <= 0:
            return jsonify(returnValue(302, "the entered amount is invalid"))
        if not userexists(to):
            return  jsonify(returnValue(303,"invalid recipient username"))
        senderBal = accountBalance(username)
        if senderBal < transfer:
            return jsonify(returnValue(304,"account balance is low"))
        recipientBal=accountBalance(to)
        bankBalance=accountBalance("bank")

        col.update({"username":username},
                   {"$set":{
                       "deposit":senderBal-transfer-5
                   }})

        col.update({"username":to},
                   {"$set":
                        {
                            "deposit":recipientBal+transfer
                        }})
        col.update({"username":"bank"},
                   {"$set":
                        {
                            "amount":bankBalance+5
                        }})

        return jsonify(returnValue(200,"transfer successful"))


class takeloan(Resource):
    def post(self):
        enteredVal = request.get_json()
        username = enteredVal["username"]
        password = enteredVal["password"]
        loan = enteredVal["amount"]
        balance=accountBalance(username)
        loanBal=debtBalance(username)
        json, error = verifyuser(username, password)
        if error:
            return jsonify(json)

        col.update({"username": username},
                   {"$set": {
                       "deposit":balance+loan,
                       "debt":loanBal+loan

                   }})
        return  jsonify(returnValue(200,"loan is given"))

class payloan(Resource):
    def post(self):
        enteredVal = request.get_json()
        username = enteredVal["username"]
        password = enteredVal["password"]
        transfer= enteredVal["amount"]

        json, error = verifyuser(username, password)
        if error:
            return jsonify(json)
        if transfer <= 0:
            return jsonify(returnValue(302, "the entered amount is invalid"))

        senderBal = accountBalance(username)
        loanbal=debtBalance(username)
        if senderBal < transfer:
            return jsonify(returnValue(304,"account balance is low"))
        if loanbal<transfer:
            return jsonify(returnValue(305,"you are paying more  that required"))
        col.update({"username": username},
                   {"$set": {
                       "deposit": senderBal - transfer,
                       "debt": loanbal -transfer

                   }})
        return jsonify(returnValue(200, "loan paid  successfully"))


class balance(Resource):
    def post(self):
        enteredVal = request.get_json()
        username = enteredVal["username"]
        password = enteredVal["password"]
        json, error = verifyuser(username, password)
        if error:
            return jsonify(json)
        senderBal = accountBalance(username)
        loanbal=debtBalance(username)
        retjson={
            "status":200,
            "balance":senderBal,
            "loanBalance":loanbal

        }
        return  jsonify(retjson)

api.add_resource(registration,"/reg")
api.add_resource(deposit ,"/deposit")
api.add_resource(transfer,"/transfer")
api.add_resource(takeloan,"/loan")
api.add_resource(payloan,"/repay")
api.add_resource(balance,"/balance")



@app.route('/')
def hello_world():
    return "Hello welcome to banking system!"


if __name__=="__main__":
    app.run(host='0.0.0.0',debug=True)
