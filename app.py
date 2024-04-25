from flask import Flask, render_template, request, redirect, url_for, flash, current_app, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import os
import PyPDF2

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# File Model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define a registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    # Custom validation to check if the username is already taken
    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            flash('That username is already taken. Please choose a different one.', 'error')
    
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/community')
@login_required
def community():
    return render_template('community.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('upload'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Custom unauthorized handler
@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('Please login to access this page.', 'info')
    return redirect(url_for('login'))


@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)

    # Check if the current user is the owner of the file
    if file.user != current_user:
        flash('You are not authorized to delete this file.', 'error')
        return redirect(url_for('upload'))

    # Delete the file from the database
    db.session.delete(file)
    db.session.commit()

    # Delete the file from the file system
    file_path = os.path.join(current_app.root_path, 'static', 'uploads', file.filename)
    os.remove(file_path)

    flash('File deleted successfully', 'success')
    return redirect(url_for('upload'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            original_filename = file.filename
            filename = original_filename
            existing_files = File.query.filter_by(filename=filename).all()
            if existing_files:
                count = 1
                while True:
                    new_filename = f"{os.path.splitext(original_filename)[0]} ({count}){os.path.splitext(original_filename)[1]}"
                    if not File.query.filter_by(filename=new_filename).first():
                        filename = new_filename
                        break
                    count += 1
            file_path = os.path.join(current_app.root_path, 'static', 'uploads', filename)
            file.save(file_path)
            new_file = File(filename=filename, user=current_user)
            db.session.add(new_file)
            db.session.commit()
            flash('File uploaded successfully', 'success')
            return redirect(url_for('upload'))
        else:
            flash('No file selected', 'error')
    files = File.query.all()
    return render_template('upload.html', files=files)


@app.route('/view/<int:file_id>')
@login_required
def view(file_id):
    file = File.query.get(file_id)
    if file:
        # Open the PDF file and extract the total number of pages
        with open(os.path.join(current_app.root_path, 'static', 'uploads', file.filename), 'rb') as pdf_file:
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            total_pages = len(pdf_reader.pages)

        return render_template('view.html', file=file, total_pages=total_pages)
    else:
        flash('File not found', 'error')
        return redirect(url_for('upload'))

# Add a route to handle user search
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        users = User.query.filter(User.username.like(f'%{search_query}%')).all()
        return render_template('search_results.html', users=users)
    return redirect(url_for('community'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
