#!/usr/bin/env python
#
# Copyright 2011 Joseph Rawlings
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
##########################################################################
import webapp2
import cgi
import string
import re

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

rot13 = string.maketrans("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                         "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM")

rot13_form = """
	<html>
		<head></head>
		<body>
			<h2>Enter some text to ROT13:</h2>
			<form method="post">
				<textarea name="text" id="ta">%(text)s</textarea>
				<input type="submit">
			</form>
		</body>
	</html>
"""
signup_form="""
	<h1>Signup</h1>
	<form method="post">
		<label> Username <input type="text" name="username" id="username" value="%(username)s"><span style="color:red">%(username_error)s</span></label><br/>
		<label> Password <input type="password" name="password" id="password" value="%(password)s"><span style="color:red">%(password_error)s</span></label><br/>
		<label> Verify Password <input type="password" name="verify" id="verify" value="%(verify)s"><span style="color:red">%(verify_error)s</span></label><br/>
		<label> Email <input type="text" name="email" id="email" value="%(email)s"><span style="color:red">%(email_error)s</span></label><br/>
		
		<input type="submit">
	</form>
"""

def escape_html(s):
    return cgi.escape(s, quote = True)

months = ['January', 
	'February', 
	'March', 
	'April', 
	'May', 
	'June', 
	'July', 
	'August', 
	'September', 
	'October', 
	'November', 
	'December'
]

month_abbvs = dict((m[:3].lower(), m) for m in months)

def valid_month(month):
	if month:
		return month_abbvs.get(month[:3].lower())

def valid_day(day):
	if day and day.isdigit() and int(day) in range(1, 32): 
		return int(day)

def valid_year(year):
	if year and year.isdigit() and int(year) in range(1900, 2021): 
		return int(year)

def valid_username(username):
	return USERNAME_RE.match(username)

def valid_password(password):
	return PASSWORD_RE.match(password)

def valid_verify(password, verify):
	return password == verify

def valid_email(email):
	return EMAIL_RE.match(email)

class ROT13Handler(webapp2.RequestHandler):
	
	def write_textarea(self, text = ""):
		self.response.out.write(rot13_form % {
			"text" : text
		})

	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		self.write_textarea()

	def post(self):
		self.write_textarea(escape_html(string.translate(self.request.get('text').encode('utf-8'), rot13)))

class SignupHandler(webapp2.RequestHandler):
	
	def write_signup(self, username="", username_error="", password="", password_error="", verify="", verify_error="", email="", email_error=""):
		self.response.out.write(signup_form % {
			'username' : username, 
			'username_error' : username_error,
			'password' : "",
			'password_error' : password_error,
			'verify' : "",
			'verify_error' : verify_error,
			'email' : email,
			'email_error' : email_error
		})

	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		self.write_signup()

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify = self.request.get('verify')
		user_email = self.request.get('email')

		username = ""
		password = ""
		verify = ""
		email = ""

		if not valid_username(user_username):
			username = "That's not a valid username."
		if not valid_password(user_password):
			password = "That wasn't a valid password."
		if not valid_verify(user_password, user_verify):
			verify = "Your passwords didn't match."
		if user_email and not valid_email(user_email):
			email = "That's not a valid email"

		if not (username == "" and password == "" and verify == "" and not (user_email and email)):
			self.write_signup(user_username, username, user_password, password, user_verify, verify, user_email, email)		
		else:
			self.redirect("/unit2/welcome?username="+user_username)

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/html'
		self.response.out.write('<h1>Welcome, ' + self.request.get('username') + '!</h1>')

app = webapp2.WSGIApplication([
		('/unit2/rot13', ROT13Handler), 
		('/unit2/signup', SignupHandler),
		('/unit2/welcome', WelcomeHandler)
	], debug=True)


