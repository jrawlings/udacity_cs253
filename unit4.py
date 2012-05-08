import webapp2
import os
import jinja2
import hmac
import string
import re
import random
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates/unit4')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)
jinja_env_escaped = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = 'mysecret'

def make_salt(size=5, chars=string.letters):
    return ''.join(random.choice(chars) for x in range(size))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	return '%s|%s' % (hashlib.sha256(name + pw + salt).hexdigest(), salt)

def valid_pw(name, pw, h):
	salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	return val if h == make_secure_val(val) else None

# RegEx for the signup form
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

# Validation for Usernames
def valid_username(username):
	return USERNAME_RE.match(username)

# Validation for Passwords
def valid_password(password):
	return PASSWORD_RE.match(password)

# Validation for Emails
def valid_email(email):
	return EMAIL_RE.match(email)

# Web App handlers
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render_str_escaped(self, template, **params):
		t = jinja_env_escaped.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_content(self, template, **kw):
		content = self.render_str_escaped(template, **kw)
		self.render("index.html", content=content)

class Entry(db.Model):
	content = db.TextProperty(required = True)
	subject = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)

class Unit4Handler(Handler):
	def render_posts(self):
		entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC")
		self.render_content("post.html", entries=entries)
	def get(self):
		self.render_posts()

class Unit4EntryHandler(Handler):
	def get(self, entry_id):
		entry = Entry.get_by_id(long(entry_id))
		entries = [ entry ]
		self.render_content("post.html", entries=entries)

class Unit4LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect("/unit4/signup")

class Unit4LoginHandler(Handler):
	def get(self):
		self.render_content("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		users = db.GqlQuery("SELECT * FROM User WHERE username = :1", username, limit=1)

		if users.count() == 1 and valid_pw(users[0].username, password, users[0].password_hash):
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(users[0].key().id())))
			self.redirect("/unit4/welcome")
		else:
			self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
			login_error="Invalid login"
			self.render_content("login.html", error=login_error)

class Unit4SingupHandler(Handler):
	def get(self):
		self.render_content("signup.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		username_error = ""
		password_error = ""
		verify_error = ""
		email_error = ""

		if not valid_username(username):
			username_error = "That's not a valid username."
		if not valid_password(password):
			password_error = "That wasn't a valid password."
		if not password == verify:
			verify_error = "Your passwords didn't match."
		if email and not valid_email(email):
			email_error = "That's not a valid email"

		if not (username_error == "" and password_error == "" and verify_error == "" and not (email and email_error)):
			self.render_content("signup.html"
				, username=username
				, username_error=username_error
				, password_error=password_error
				, verify_error=verify_error
				, email=email
				, email_error=email_error)
		else:
			user = User(username=username, password_hash=make_pw_hash(username, password), email=email)
			user.put()
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(user.key().id())))
			self.redirect("/unit4/welcome")

class Unit4WelcomeHandler(Handler):
	def get(self):
		user_id = 0
		user = None
		user_id_str = self.request.cookies.get('user_id')
		if user_id_str:
			user_id = check_secure_val(user_id_str)

		if not user_id:
			self.redirect("/unit4/signup")
		else:
			user = User.get_by_id(long(user_id))
			self.render_content("welcome.html", user=user)

class Unit4NewPostHandler(Handler):

	def render_new_post(self, subject="", content="", error=""):
		self.render_content("new_post.html", subject=subject, content=content, error=error)

	def get(self):
		self.render_new_post()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			entry = Entry(subject = subject, content = content)
			entry.put()
			self.redirect("/unit4/" + str(entry.key().id()))
		else:
			error = "subject and content, please!"
			self.render_new_post(subject=subject, content=content, error = error)

app = webapp2.WSGIApplication([
		  ('/unit4', Unit4Handler)
		, ('/unit4/newpost', Unit4NewPostHandler)
		, ('/unit4/login', Unit4LoginHandler)
		, ('/unit4/logout', Unit4LogoutHandler)
		, ('/unit4/signup', Unit4SingupHandler)
		, ('/unit4/welcome', Unit4WelcomeHandler)
		, ('/unit4/(\d+)', Unit4EntryHandler)
	], debug=True)


