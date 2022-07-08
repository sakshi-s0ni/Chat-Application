from flask import Flask,jsonify,flash,request,make_response,render_template,abort,redirect,url_for
from functools import wraps
import jwt
import sqlite3 as lite
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO,send,emit
import os,os.path

app = Flask(__name__)

bcrypt = Bcrypt(app)
socketio = SocketIO(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245' #used for tokens

con = lite.connect('site.db')
with con:
	cur = con.cursor()
	cur.execute("CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, sender TEXT , receiver Text , message1 , message2)")
	cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT , password TEXT , token TEXT , public_key)")

users = {}

def session_authorization(f):
	@wraps(f)
	def decorator(*args, **kwargs):
		token_cookie = request.cookies.get('token')

		if not token_cookie:
			abort(403)
		return f(*args,**kwargs)
	return decorator

def token_authorization(f):         #Authentication
	@wraps(f)
	def decorator(*args,**kwargs):
		token_cookie = request.cookies.get('token')

		if not token_cookie:
			abort(403)

		con = lite.connect('site.db')
		with con:
			cur = con.cursor()
			cur.execute("select * FROM users")
			while True:
				row = cur.fetchone()
				if row == None:
					abort(403)
				if bcrypt.check_password_hash(row[3],token_cookie):
					return f(*args, **kwargs)

	return decorator

@app.route('/')
def home():
	return render_template ('home.html')

@app.route('/register', methods = ['POST', 'GET'])
def register():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['pass']
		confirm_password = request.form['confirm_pass']
		public_key = request.form['public_key']

		if username == '' or password == '' or confirm_password == '':
			return jsonify(message = 'Please enter details in the input field!' , result = 'no')

		con = lite.connect('site.db')
		with con:
			cur = con.cursor()
			cur.execute("select * FROM users")
			while True:
				row = cur.fetchone()
				if row == None:
					break
				if row[1] == username:
					return jsonify(message = 'Username already exists! Please enter another username' , result = 'no')
			
			if not password == confirm_password:
				return jsonify(message = 'Password does not match! Please enter details again' , result = 'no')

			#generate private and public key and save the private key in a file
			#in pc and public key in keys table in database

			#key generation

			#storing public_key in database 'users'

			hashed_pass = bcrypt.generate_password_hash(password).decode('utf-8')
			token = jwt.encode({'user' : username} , app.config['SECRET_KEY'])
			hashed_token = bcrypt.generate_password_hash(token).decode('utf-8')

			# i have to store token hash in my database
			cur.execute("INSERT INTO users (username,password,token,public_key) VALUES (?,?,?,?)",(username,hashed_pass,hashed_token,public_key))	
			return jsonify(message = 'Registered successfully! Please login now.', result = 'yes')

	return render_template('register.html', message = '')

@app.route('/login', methods = ['GET','POST'])
def login():
	token_cookie = request.cookies.get('token')
	if token_cookie:
		return redirect(url_for('user'))

	if request.method == 'POST':
		username = request.form['username']
		password = request.form['pass']
		key_status = request.form['key_status']

		con = lite.connect('site.db')
		with con:
			cur = con.cursor()
			cur.execute("select * FROM users")
			while True:
				row = cur.fetchone()
				if row == None:
					break
				if row[1] == username:
					if bcrypt.check_password_hash(row[2],password):
						if key_status == 'yes':
							token = jwt.encode({'user' : username} , app.config['SECRET_KEY'])
							token = token.decode('UTF-8')
							my_public_key = row[4]
							return jsonify(message = 'Logged in successfully!', result = 'yes' , token = token , my_public_key = my_public_key)
						else:
							return jsonify(message ='Please log in from registered device or from the registered browser!', result = 'no')
					else:
						return jsonify(message = 'Incorrect password! Please enter again', result = 'no')

			return jsonify(message = 'Invalid username! Please enter again', result = 'no')

	return render_template('login.html')

@app.route('/user')
@token_authorization
def user():
	token_cookie = request.cookies.get('token')
	username = jwt.decode(token_cookie,app.config['SECRET_KEY'])['user']

	all_users = []

	con = lite.connect('site.db')
	with con:
		cur = con.cursor()
		cur.execute("select * FROM users ORDER BY username ASC")
		while True:
			row = cur.fetchone()
			if row == None:
				break
			if row[1] != username:
				all_users = all_users + [row[1]]

	return render_template('user.html', all_users = all_users, username = username)

@app.route("/message", methods = ['GET','POST'])
@token_authorization
def message():
	receiver_username = request.form['receiver_username']
	username = request.form['username']

	conversations =[]

	con = lite.connect('site.db')
	with con:
		cur = con.cursor()
		cur.execute("select * from messages")
		while True:
			row = cur.fetchone()
			if row == None:
				break
			if row[1] == username and row[2] == receiver_username:
				conversations = conversations + [row[1]]

				# decrypt this message(row[3]) with my private key and then
				# pass in conversatiions
				conversations = conversations + [row[3]]
			if row[1] == receiver_username and row[2] == username:
				conversations = conversations + [row[1]]

				# decrypt this message(row[4]) with my private key and then
				# pass in conversatiions
				conversations = conversations + [row[4]]

		cur.execute("select * from users")
		while True:
			row = cur.fetchone()
			if row == None:
				break
			if row[1] == receiver_username:
				receiver_public_key = row[4]
				break

	return jsonify(conversations = conversations, receiver_public_key = receiver_public_key)

@socketio.on('session_id')
@session_authorization
def session_id():
	token_cookie = request.cookies.get('token')
	username = jwt.decode(token_cookie,app.config['SECRET_KEY'])['user']

	for user in users:
		if user == username:
			got_session_id = users.get(user)
			users[username] = request.sid
			emit('session_id', room = got_session_id )

	users[username] = request.sid

@socketio.on('message')
def handle_my_custom_event(username_receiver,message1,message2,username_sender):

	con = lite.connect('site.db')
	with con:
		cur = con.cursor()
		cur.execute("INSERT INTO messages (sender , receiver , message1,message2) VALUES (?,?,?,?)",(username_sender,username_receiver , message1, message2))

	conversations =[]
	conversations2 = []

	with con:
		cur = con.cursor()
		cur.execute("select * from messages")
		while True:
			row = cur.fetchone()
			if row == None:
				break
			if row[1] == username_sender and row[2] == username_receiver:
				conversations = conversations + [row[1]]
				conversations2 = conversations2 + [row[1]]

				# decrypt this message(row[3]) with my private key and then
				# pass in conversatiions
				conversations = conversations + [row[3]]
				conversations2 = conversations2 + [row[4]] 
			if row[1] == username_receiver and row[2] == username_sender:
				conversations = conversations + [row[1]]
				conversations2 = conversations2 +[row[1]]

				# decrypt this message(row[4]) with my private key and then
				# pass in conversatiions
				conversations = conversations + [row[4]]
				conversations2 = conversations2 + [row[3]]

	ans = 0
	for user in users:
		if user == username_receiver:
			ans = 1
			recipient_session_id = users[username_receiver]
			my_session_id = users[username_sender]
			emit('message', [conversations2, username_sender] , room = recipient_session_id)
			emit('message', [conversations, username_sender] , room = my_session_id)
			break

	if ans == 0:
		my_session_id = users[username_sender]
		emit('message', [conversations, username_sender] , room = my_session_id)


if __name__ == '__main__':
	socketio.run(app, debug=True)