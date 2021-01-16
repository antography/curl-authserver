from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, leave_room
from flask_cors import CORS, cross_origin
from flask import jsonify
from random import randint
import time
import os, sys
import bcrypt, html
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
  data = {
    'anon': bool(config['general']['anonymous']),
    'registration': bool(config['general']['registration'])
  }
  socketio.emit('authProvInfo', data, room=request.sid)


@socketio.on('register')
def socket_register(json):
  res = 1

  if ((json['password'] or json['username']) == ""):
    res = -1

  hashed = bcrypt.hashpw(json['password'].encode('utf8'), bcrypt.gensalt())
  userId = genKey()
  username = html.escape(json['username'])

  data = {
    'username': username,
    'hashed': hashed.decode("utf-8"),
    'ID': userId
  }

  try:
    cursor.execute( "INSERT INTO users (id, username, password) VALUES (?, ?, ?)", (userId, username, hashed))
    conn.commit()

  except mariadb.Error:
    res = -2

  if res == -1:
    socketio.emit("message", "Username or Password is empty", room=request.sid)
  if res == -2:
    socketio.emit("message", "Database did a doozy", room=request.sid)

  if res > 0:
    socketio.emit ("message", data, room=request.sid)


if __name__ == '__main__':
    socketio.run(app)