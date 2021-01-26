from flask import Flask, render_template, request, make_response, redirect, send_file, send_from_directory
from flask_socketio import SocketIO, join_room, leave_room
from flask_cors import CORS, cross_origin
from flask import jsonify
from random import randint
import time
import os, sys
import bcrypt, html, hashlib
import mariadb
import configparser
import hmac

config = configparser.ConfigParser()
config.read('config.ini')

try:
  conn = mariadb.connect(
      user=config['database']['username'],
      password=config['database']['password'],
      host=config['database']['host'],
      port= int(config['database']['port']),
      database=config['database']['db']

  )
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

# Get Cursor
cursor = conn.cursor()

def genKey():

  currTime = bin(round(time.time() * 1000))[2:]
  currPid = bin(os.getpid())[2:]
  currRand = bin(randint(1, 2361183241434822606848))[2:].zfill(71)

  formatted = ( currTime + currPid + currRand)[0:64]
  res = int(formatted, 2) # dont worry about it :D
  return res


app = Flask(__name__)
app.config['_KEY'] = genKey()
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def hello_world():
    return 'Hello, World!'

@socketio.on('message')
def handle_message(data):
    print('received message: ' + data)

@socketio.on('connect')
def handle_message():
  # Tell the connecting client what the authentication provider can do
  data = {
    'anon': bool(config['general']['anonymous']),
    'registration': bool(config['general']['registration'])
  }
  socketio.emit('authProvInfo', data, room=request.sid)


@app.route('/register', methods=['POST'])
def post_register():
  json = request.form
  ref = json['ref']

  # Make sure nothing is null
  if (json['password']  == '' or json['username']  == '' or json['authprovider'] == ''):
    return redirect(ref)

  # lightly sanatize the username
  username = html.escape(json['username'])

  # Make sure the user doesnt exist already
  try:
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))

  except mariadb.Error as e:
    print (e)
    return redirect(ref)

  # If the user exists, then nope out
  if (cursor.fetchone() != None):
    return redirect(ref)   
  
  hashed = bcrypt.hashpw(json['password'].encode('utf8'), bcrypt.gensalt())
  userId = genKey()
  sessionId = hashlib.md5(str(genKey()).encode('utf8')).hexdigest()

  try:
    cursor.execute( "INSERT INTO users (id, username, password) VALUES (?, ?, ?)", (userId, username, hashed))
    conn.commit()
  except mariadb.Error:
   return "Database died"

  try:
    cursor.execute( "INSERT INTO sessions (uid, sid) VALUES (?, ?)", (userId, sessionId))
    conn.commit()
  except mariadb.Error:
    return "Database did a doozy"


  # Success redirect with cookies
  response = make_response(redirect('http://127.0.0.1:5500/app/index.html'))
  response.set_cookie('session_id', sessionId)
  response.set_cookie('auth_provider', json['authprovider'])
  return response

@app.route('/login', methods=['POST'])
def post_login():
  json = request.form
  ref = json['ref']

  username = html.escape(json['username'])
  # Make sure the user is real on this authprov
  try:
    cursor.execute("SELECT username,password, id FROM users WHERE username=?", (username,))

  except mariadb.Error as e:
    print (e)
    return redirect(ref)
  # If the user doesnt exist then nope out
  row = cursor.fetchone()
  if (row == None):
    return redirect(ref)   

  if not (bcrypt.checkpw(json['password'].encode('utf8'), row[1].encode('utf8'))):
    return redirect(ref)

  sessionId = hashlib.md5(str(genKey()).encode('utf8')).hexdigest()

  try:
    cursor.execute( "INSERT INTO sessions (uid, sid) VALUES (?, ?)", (row[2], sessionId))
    conn.commit()
  except mariadb.Error:
    return "Database did a doozy"

  response = make_response(redirect('http://127.0.0.1:5500/app/index.html'))
  response.set_cookie('session_id', sessionId)
  response.set_cookie('auth_provider', json['authprovider'])
  return response


@app.route('/pfp/<uid>')
def send_js(uid):
    return send_from_directory("./pfp/", f'{uid}.jpg')


@socketio.on('connect', namespace = "/user")
def handle_message():
  # Tell the connecting client what the authentication provider can do
  data = {
    'anon': bool(config['general']['anonymous']),
    'registration': bool(config['general']['registration'])
  }
  socketio.emit('authProvInfo', data,  room=request.sid, namespace = "/user")

@socketio.on('getUserInfo', namespace = "/user")
def userInfo(sessionID = ""):
  if sessionID == "":
    return

  try:
    cursor.execute("SELECT * FROM users WHERE id=(SELECT uid FROM sessions WHERE sid=?)", (sessionID,))

  except mariadb.Error as e:
    print (e)

  row = cursor.fetchone()
  if (row == None):
    return

  try:
    cursor.execute("SELECT * FROM buildings WHERE uid=?", (row[0],))

  except mariadb.Error as e:
    print (e)
  
  res = {
    'userId': row[0],
    'username': row[1],
    'pfp': bool(row[3]),
    'subtitle': row[6],
    'guest': row[8]
  }
  socketio.emit('userInfo', res,  room=request.sid, namespace = "/user")

if __name__ == '__main__':
    socketio.run(app, debug= True)