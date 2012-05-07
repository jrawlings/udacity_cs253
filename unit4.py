import webapp2
import os
import jinja2
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)
jinja_env_escaped = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = 'joessecret'

def make_salt(size=5, chars=string.letters):
    return ''.join(random.choice(chars) for x in range(size))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
    return '%s,%s' % (hashlib.sha256(name + pw + salt).hexdigest(), salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	return val if h == make_secure_val(val) else None

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

class Unit4Handler(Handler):

	def render_posts(self):
		entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC")
		self.render_content("post.html", entries=entries)
	def get(self):
		self.render_posts()

		visits = 0
		visits_cook_str = self.request.cookies.get('visits')
		if visits_cook_val:
			cookie_val = check_secure_val(visits_cook_str)
			if cookie_val:
				visits = int(cookie_val)
		
		visits += 1
		new_cookie_val = make_secure_val(str(visits))

		self.response.headers.add_header('Set-Cookie', 'visits=%s' % visits)


class Unit4EntryHandler(Handler):
	def get(self, entry_id):
		entry = Entry.get_by_id(long(entry_id))
		entries = [ entry ]
		self.render_content("post.html", entries=entries)

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
		, ('/unit4/(\d+)', Unit4EntryHandler),
	], debug=True)


