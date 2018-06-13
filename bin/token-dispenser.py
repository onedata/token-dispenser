#!/usr/bin/env python3
from flask import Flask
from flask import request
import requests, sys, json, yaml
import hashlib

app = Flask(__name__)

idps = None

@app.route('/')
def index():
  return "Usage: /api/v1.0/token/<idp>"

# Get Onezone API token using basic auth
def getOnezoneTokenWithBAsicAuth(username,password,url):
  response=requests.post("{}/{}".format(url,"api/v3/onezone/user/client_tokens"), auth=(username, password), verify=False)
  response.raise_for_status()
  return json.loads(response.content)["token"]
  
# Get Onezone API token with auth token
def getOnezoneTokenWithToken(token,url):
  response=requests.post("{}/{}".format(url,"api/v3/onezone/user/client_tokens"),
    headers={
      "X-Auth-Token": "{}".format(token)
    },
    verify=False,
    )
  response.raise_for_status()
  return json.loads(response.content)["token"]

# Get Keycloak access token
def getKeycloakToken(username,password,url):
  response=requests.post("{}/{}".format(url,"auth/realms/onedata/protocol/openid-connect/token"),
    headers={
      "Content-Type": "application/x-www-form-urlencoded"
    },
    data={
      "username": username,
      "password": password,
      "grant_type": "password",
      "client_id": "admin-cli"
    },
    verify=False,
    )
  return json.loads(response.content)["access_token"]

@app.route('/api/v1.0/token/<idp>', methods=['GET'])
def get_token(idp):
  username=request.authorization["username"]
  password=request.authorization["password"]
  idp_type=idps[idp]["type"]
  try:
    if idp_type == "onepanel":
      token = getOnezoneTokenWithBAsicAuth(username,password,idps[idp]['url'])
    elif idp_type == "keycloak":
      keycloakToken = getKeycloakToken(username,password,idps[idp]['url'])
      token = getOnezoneTokenWithToken("{}:{}".format(idps[idp]['tokenPrefix'],keycloakToken),idps[idp]['onezoneUrl'])
  except requests.exceptions.HTTPError as err:
      return "{}".format(err)
  return "{}".format(token)
  
  
# Get Keycloak user info
def getKeycloakUserInfo(token,url):
  response=requests.get("{}/{}".format(url,"auth/realms/onedata/protocol/openid-connect/userinfo"),
    headers={
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": "{} {}".format("Bearer",token)
    },
    verify=False,
    )
  response.raise_for_status()
  return json.loads(response.content)

# Get Onezone user info
def getOnezoneUserInfo(username,password,url):
  response=requests.get("{}/{}".format(url,"api/v3/onezone/user"), auth=(username, password), verify=False)
  response.raise_for_status()
  return json.loads(response.content)

@app.route('/api/v1.0/onezone/uid/<idp>', methods=['GET'])
def get_uid(idp):
  username=request.authorization["username"]
  password=request.authorization["password"]
  idp_type=idps[idp]["type"]
  try:
    if idp_type == "onepanel":
      uid = getOnezoneUserInfo(username,password,idps[idp]['url'])['userId']
      print(uid)
    elif idp_type == "keycloak":
      token = getKeycloakToken(username,password,idps[idp]['url'])
      keycloakUid = getKeycloakUserInfo(token,idps[idp]['url'])['sub']
      uid = hashlib.md5("{}:{}".format(idps[idp]['name'],keycloakUid).encode()).hexdigest()
  except requests.exceptions.HTTPError as err:
      return "{}".format(err)
  return uid
  
@app.route('/api/v1.0/user/info/<idp>', methods=['GET'])
def get_userInfo(idp):
  username=request.authorization["username"]
  password=request.authorization["password"]
  idp_type=idps[idp]["type"]
  try:
    if idp_type == "onepanel":
      userinfo = getOnezoneUserInfo(username,password,idps[idp]['url'])
    elif idp_type == "keycloak":
      token = getKeycloakToken(username,password,idps[idp]['url'])
      userinfo = getKeycloakUserInfo(token,idps[idp]['url'])
      userinfo = {
        'userId': hashlib.md5("{}:{}".format(idps[idp]['tokenPrefix'],userinfo['sub']).encode()).hexdigest(),
        'name': userinfo['name'],
        'login': userinfo['preferred_username'],
        'linkedAccounts': [],
        'emailList': [ userinfo['email'] ]
        }
  except requests.exceptions.HTTPError as err:
      return "{}".format(err)
  return json.dumps(userinfo)

if __name__ == '__main__':
    idps = yaml.load(open(sys.argv[1], "r"))["idps"]
    app.run(host='0.0.0.0', port=sys.argv[2],debug=False)
    
    
    
