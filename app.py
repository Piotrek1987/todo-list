from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)

# App Config
app.config['SECRET_KEY'] = 'welcometomytodolist11'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and login manager
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Serializer setup
s = URLSafeTimedSerializer(app.secret_key)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    due_date = db.Column(db.DateTime, nullable=True)  # Add the due_date column
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Load user function for flask-login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes

# Home route (show tasks)
@app.route('/')
@login_required
def home():
    now = datetime.now()
    search = request.args.get('search', '')

    if search:
        tasks = Task.query.filter(
            Task.user_id == current_user.id,
            Task.description.ilike(f"%{search}%")
        ).order_by(Task.due_date.asc()).all()
    else:
        tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.due_date.asc()).all()

    return render_template('index.html', tasks=tasks, now=now, timedelta=timedelta)


# Add task route
@app.route('/add', methods=['POST'])
@login_required
def add_task():
    description = request.form.get('description')
    due_date_str = request.form.get('due_date')

    due_date = None
    if due_date_str:
        due_date = datetime.strptime(due_date_str, '%Y-%m-%dT%H:%M')

    new_task = Task(description=description, user_id=current_user.id, due_date=due_date)
    db.session.add(new_task)
    db.session.commit()
    flash('Task added successfully!')
    return redirect(url_for('home'))

# Mark task as completed
@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get(task_id)
    task.completed = True
    db.session.commit()
    flash('Task completed!')
    return redirect(url_for('home'))

# Delete task
@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted!')
    return redirect(url_for('home'))

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if user exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        login_user(new_user)
        return redirect(url_for('home'))

    return render_template('signup.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('username_or_email')  # updated field name
        password = request.form.get('password')

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

        flash('Invalid credentials', 'error')

    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('login'))

@login_manager.unauthorized_handler
def unauthorized():
    flash('Please log in to access this page.', 'error')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            print(f"Password reset link (simulate sending email): {reset_url}")
            flash('Password reset link sent! Check console (simulated).', 'info')
        else:
            flash('Email not found.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', token=token))

        if len(new_password) < 6:
            flash('Password should be at least 6 characters long.', 'error')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password has been reset!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)

    if task.user_id != current_user.id:
        flash("You can't edit this task.", "error")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_description = request.form.get('title', '').strip()
        print("New title submitted:", new_description)  # Debugging line
        task.description = new_description

        due_date_str = request.form.get('due_date')
        if due_date_str:
            try:
                task.due_date = datetime.strptime(due_date_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash("Invalid date format.", "error")
                return render_template('edit_task.html', task=task)
        else:
            task.due_date = None

        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('edit_task.html', task=task)





if __name__ == '__main__':
    app.run(debug=True)
