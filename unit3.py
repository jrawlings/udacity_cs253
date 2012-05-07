import webapp2
import os
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)
jinja_env_escaped = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

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

class Unit3Handler(Handler):

	def render_posts(self):
		entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC")
		self.render_content("post.html", entries=entries)
	def get(self):
		self.render_posts()

class Unit3EntryHandler(Handler):
	def get(self, entry_id):
		entry = Entry.get_by_id(long(entry_id))
		entries = [ entry ]
		self.render_content("post.html", entries=entries)

class Unit3NewPostHandler(Handler):

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
			self.redirect("/unit3/" + str(entry.key().id()))
		else:
			error = "subject and content, please!"
			self.render_new_post(subject=subject, content=content, error = error)

app = webapp2.WSGIApplication([
		  ('/unit3', Unit3Handler)
		, ('/unit3/newpost', Unit3NewPostHandler)
		, ('/unit3/(\d+)', Unit3EntryHandler),
	], debug=True)


