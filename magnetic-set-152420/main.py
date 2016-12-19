import os
import re
from string import letters
import random

import webapp2
import jinja2
import hmac
import time

from google.appengine.ext import db

# for jinja templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Cookie functions


def make_hash(s):
    return hmac.new(SECRET, s).hexdigest()


def make_cookie(s):
    return '%s|%s' % (s, make_hash(s))

# checks and returns if the cookie is valid


def check_cookie(cookie):
    val = cookie.split('|')[0]
    if cookie == make_cookie(val):
        return val


def get_user_id(self):
    cookie = self.request.cookies.get('user_id')
    if cookie and check_cookie(cookie):
        return cookie.split('|')[0]


# password hashing
# for hashing, not to include in production
SECRET = '142arsgdf354rasf3q451afsd'


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hmac.new(SECRET, name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def check_pw_hash(name, pw, pw_hash):
    salt = pw_hash.split(',')[0]
    return pw_hash == make_pw_hash(name, pw, salt)


# Databases
class User(db.Model):
    ''' database for users '''
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.EmailProperty(required=False)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, username, pw, email=None):
        pw_hash = make_pw_hash(username, pw)
        return User(username=username,
                    pw_hash=pw_hash,
                    email=email)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Blog(db.Model):
    ''' database for blogs '''
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    like_count = db.IntegerProperty(default=0)
    liked = db.ListProperty(str)

    # Keeps the white space formatting
    def render(self, template, user_id):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str(template, post=self, user_id=user_id)


def comment_key(name='default'):
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    ''' database for comments '''
    blog_id = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_blog(cls, name):
        c = cls.all().filter('blog_id =', str(name)).order('created')
        return c

    # Keeps the white space formatting
    def render(self, template, user_id):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str(template, comment=self, user_id=user_id)


class Handler(webapp2.RequestHandler):
    ''' Main handler, rendering functions '''

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie = make_cookie(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' %
            (name, str(cookie)))

    def login(self, user):
        self.set_cookie('user_id', user)

    # deletes cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

# Regex to check signup info
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r'^.{3,20}$')


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class SignupHandler(Handler):

    def get(self):
        user_id = get_user_id(self)
        self.render('signup.html', user_id=user_id)

    def post(self):
        have_error = False
        username = self.request.get('username').lower()
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username, email=email)

        if not valid_username(username):
            params['error_username'] = 'Invalid Username'
            have_error = True
        if User.by_name(username):
            params['error_username'] = 'Username already taken'
            have_error = True

        if not valid_password(password):
            params['error_password'] = 'Invalid Password'
            have_error = True
        if password != verify:
            params['error_password'] = 'Passwords do not match'
            params['error_verify'] = params['error_password']
            have_error = True

        if not valid_email(email):
            params['error_email'] = 'Invalid email'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            u = User.register(username, password, email=None)
            u.put()
            self.set_cookie('user_id', username)
            self.redirect('/')


class LoginHandler(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        error = ''
        username = self.request.get('username').lower()
        password = self.request.get('password')

        u = User.by_name(username)

        if not u:
            error = 'Username does not exist'

        if u and not check_pw_hash(u.username, password, u.pw_hash):
            error = 'Incorrect password'

        if not username or not password:
            error = 'All fields required'

        if error:
            self.render('login.html', error=error)
        else:
            self.set_cookie('user_id', username)
            self.redirect('/')


class LogoutHandler(Handler):

    def get(self):
        self.logout()
        self.redirect('/')


class NewPostHandler(Handler):

    def get(self):
        user_id = get_user_id(self)
        if not user_id:
            self.redirect('/login')
        else:
            self.render('newpost.html', user_id=user_id)

    def post(self):
        user_id = get_user_id(self)
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = get_user_id(self)

        if not user_id:
            self.redirect('/login')
        elif subject and content:
            b = Blog(
                parent=blog_key(),
                subject=subject,
                content=content,
                author=author)
            b.liked.append(user_id)    
            b.put()
            self.redirect('/blog/%s' % str(b.key().id()))
        else:
            error = 'Both fields are required'
            self.render('newpost.html', error=error)


class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return self.render('404.html')

        blog_id = post.key().id()
        user_id = get_user_id(self)
        comments = Comment.by_blog(blog_id)

        if comments:
            self.render(
                'permalink.html',
                post=post,
                user_id=user_id,
                comments=comments)
        else:
            self.render('permalink.html', post=post, user_id=user_id)

    def post(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        blog_id = post.key().id()
        user_id = get_user_id(self)
        content = self.request.get('content')
        comments = Comment.by_blog(blog_id)
        likes = self.request.get('like')
        liked = post.liked

        if user_id:
            if likes and not (user_id in liked):
                post.like_count = int(likes) + post.like_count
                post.liked.append(user_id)
                post.put()
                self.render(
                    'permalink.html',
                    post=post,
                    user_id=user_id,
                    comments=comments)

        # to add comments
            elif content:
                c = Comment(
                    parent=comment_key(),
                    blog_id=post_id,
                    author=user_id,
                    content=content)
                c.put()
                time.sleep(0.5)
                comments = Comment.by_blog(blog_id)
                self.render(
                    'permalink.html',
                    post=post,
                    user_id=user_id,
                    comments=comments)

        # if post happens without a like or a comment, then it means comment
        # was left blank
            else:
                error = "Error - Comment Blank"
                self.render(
                    'permalink.html',
                    post=post,
                    user_id=user_id,
                    comments=comments,
                    error=error)

        else:
            self.redirect('/')


class EditPost(Handler):

    def get(self, post_id):
        user_id = get_user_id(self)
        if not user_id:
            self.redirect('/login')
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        # make sure logged in user is the author
        if post.author == user_id:
            self.render('editpost.html', post=post, user_id=user_id)
        else:
            error = 'Only %s can make changes to this post' % post.author
            self.render('login.html', error=error, username=post.author)

    def post(self, post_id):
        user_id = get_user_id(self)
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')

        if not user_id:
            self.redirect('/login')
        elif subject and content:
            post.subject = subject
            post.content = content
            post.put()
            time.sleep(0.25)
            self.redirect('/')
        else:
            error = 'Both a subject and content is required'
            self.render('editpost.html', post=post, error=error)


class DeletePost(Handler):

    def get(self, post_id):
        user_id = get_user_id(self)
        if not user_id:
            self.redirect('/login')
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        # make sure logged in user is the author
        if post.author == user_id:
            self.render('delete.html', post=post, user_id=user_id)
        else:
            self.redirect(
                '/login?username=%s' %
                (post.author))

    def post(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = get_user_id(self)
        delete = self.request.get('delete')


        if not user_id:
            self.redirect('/login')
        elif post.author == user_id and delete == "True":
            post.delete()
            time.sleep(0.25)
            self.redirect('/')
        else:
            self.redirect('/')


class CommentDelete(Handler):

    def get(self, comment_id):
        user_id = get_user_id(self)
        key = db.Key.from_path(
            'Comment',
            int(comment_id),
            parent=comment_key())
        comment = db.get(key)
        blog_id = comment.blog_id

        if not user_id:
            self.redirect('/login')
        elif user_id == comment.author:
            comment.delete()
            time.sleep(0.25)
            self.redirect('/blog/%s' % blog_id)
        else:
            self.redirect('/login')


class CommentEdit(Handler):

    def get(self, comment_id):
        user_id = get_user_id(self)
        if not user_id:
            self.redirect('/login')

        key = db.Key.from_path(
            'Comment',
            int(comment_id),
            parent=comment_key())
        comment = db.get(key)
        blog_id = comment.blog_id
        key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.by_blog(blog_id)

        if user_id == comment.author:
            self.render(
                'permalink.html',
                post=post,
                user_id=user_id,
                content=comment.content,
                comment_id=comment.key().id(),
                comments=comments)
            time.sleep(0.25)
        else:
            self.redirect('/blog/%s' % blog_id)

    def post(self, comment_id):
        user_id = get_user_id(self)
        key = db.Key.from_path(
            'Comment',
            int(comment_id),
            parent=comment_key())
        comment = db.get(key)
        content = self.request.get("content")

        if not user_id:
            self.redirect('/login')
        elif user_id == comment.author and content:
            comment.content = content
            comment.put()
            time.sleep(0.25)
            self.redirect('/blog/%s' % comment.blog_id)
        else:
            self.redirect('/login')

# Home page which shows all blogs


class HomePageHandler(Handler):

    def get(self):
        user_id = get_user_id(self)
        posts = Blog.all().order('-created')
        self.render('home.html', user_id=user_id, posts=posts)

    # to handle likes on the front page
    def post(self):
        user_id = get_user_id(self)
        posts = Blog.all().order('-created')
        like = self.request.get('like')
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)

        # make sure valid user logged in
        if user_id and like and not (user_id in post.liked):
            post.like_count += int(like)
            post.liked.append(user_id)
            post.put()
            time.sleep(0.25)
            self.render('home.html', user_id=user_id, posts=posts)
        else:
            login_error = "Please login to rate"
            self.render('login.html', login_error=login_error)


app = webapp2.WSGIApplication([
    ('/', HomePageHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/signup', SignupHandler),
    ('/newpost', NewPostHandler),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/([0-9]+)/edit', EditPost),
    ('/blog/([0-9]+)/delete', DeletePost),
    ('/comment/([0-9]+)/delete', CommentDelete),
    ('/comment/([0-9]+)/edit', CommentEdit)
], debug=True)