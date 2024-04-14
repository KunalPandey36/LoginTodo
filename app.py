from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
db = SQLAlchemy(app)


if __name__ == '__main__':
    app.run(debug=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


tables_created = False
@app.before_request
def create_tables_if_necessary():
    global tables_created
    if not tables_created:
        db.create_all()
        tables_created = True


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer,nullable=False)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Integer, default=0)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Todo {self.id}>'
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first() is not None:
            flash('Username is already taken.')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        # Handle POST request (add task)
        task_content = request.form['content']
        new_task = Todo(content=task_content, userid=current_user.id)
        try:
            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully', 'success')
        except:
            flash('Error adding task', 'error')
        # Redirect to the dashboard to prevent resubmission on page refresh
        return redirect(url_for('dashboard'))
        
    # Fetch tasks for the current user
    tasks = Todo.query.filter_by(userid=current_user.id).order_by(Todo.date_created).all()
    return render_template('dashboard.html', tasks=tasks)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
def delete(id):
    task_delete = Todo.query.get_or_404(id)
    
    try:
        db.session.delete(task_delete)
        db.session.commit()
        return redirect('/dashboard')
    except:
        return "There was a problem deleteing the task"
    
@app.route('/update/<int:id>',methods=['POST','GET'])
def update(id):
    task = Todo.query.get_or_404(id)

    if request.method == 'POST':
        task.content = request.form['content']
        try:
            db.session.commit()
            return redirect('/dashboard')
        except:
            return "Error updating the task"
    else:
        return render_template('update.html',task = task)



