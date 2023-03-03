from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedbackdb"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def redirect_register():
    """redirects to /register"""
    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def show_register_form():
    """Shows the form to register. Adds user to users table and adds username to session"""
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken.  Please pick another')
            return render_template('register.html', form=form)
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f'/users/{new_user.username}')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Shows login form for user. Adds their username to session."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f'Welcome Back, {user.username}!')
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Ivalid username/password']
    return render_template('login.html', form=form)


@app.route('/logout')
def logout_user():
    """Logs the user out. Removes username from session"""
    session.pop('username')
    return redirect('/')


@app.route('/users/<string:username>')
def show_user_page(username):
    """Shows user details, shows all of users feedback"""
    if 'username' not in session:
        flash('Please login first')
        return redirect('/')
    user = User.query.get_or_404(username)
    return render_template('userpage.html', user=user)
   

@app.route('/users/<string:username>/delete', methods=['POST'])
def delete_user(username):
    """Deletes the user from the database and logs them out by removing their username from session"""
    if 'username' not in session:
        flash('You must be logged in to complete that action')
        return redirect('/')
    user = User.query.get_or_404(username)
    if user.username == session['username']:
        db.session.delete(user)
        db.session.commit()
        flash("Your account has been deleted")
        session.pop('username')
        return redirect('/')
    flash("You do not have permission to complete that action")
    return redirect(f'users/{username}')

@app.route('/users/<string:username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Shows form to add feedback, accepts post request from form and redirects to root"""
    if 'username' not in session:
        flash('You must be logged in to complete that action')
        return redirect('/')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        feedback = Feedback(title=title, content=content, username=username)
        if username == session['username']:
            db.session.add(feedback)
            db.session.commit()
            return redirect (f'/users/{username}')
        flash("You do not have permission to complete that action")
    return render_template('addfeedback.html', form=form)

@app.route('/feedback/<int:id>/update', methods=['GET', 'POST'])
def edit_feedback(id):
    """Shows form to edit a specific feedback and handles request to update the feedback"""
    if 'username' not in session:
        flash('You must be logged in to complete that action')
        return redirect('/')
    feedback = Feedback.query.get_or_404(id)
    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        if feedback.user.username == session['username']:
            db.session.commit()
            return redirect (f'/users/{feedback.user.username}')
        flash("You do not have permission to complete that action")
    return render_template('editfeedback.html', form=form)

@app.route('/feedback/<int:id>/delete', methods=["POST"])
def delete_feedback(id):
    """Delete the specific feedback"""
    if 'username' not in session:
        flash('You must be logged in to complete that action')
        return redirect('/')
    feedback = Feedback.query.get_or_404(id)
    if feedback.user.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        return redirect(f'/users/{feedback.user.username}')
    flash("you do not have permission to do that!")
    return redirect(f'/users/{feedback.user.username}')



