from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'landing'

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    abbreviation = db.Column(db.String(10), nullable=False)
    reg_number = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return '<Organization %r>' % self.id

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.String(20), nullable=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return '<User %r>' % self.id

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return redirect(url_for('landing'))

@app.route('/index', methods=['POST', 'GET'])
@login_required
def index():
    if request.method == 'POST':
        organization_name = request.form.get('name')
        organization_abbreviation = request.form.get('abbreviation')
        organization_reg_number = request.form.get('reg_number')

        if organization_name and organization_abbreviation and organization_reg_number:
            new_organization = Organization(
                name=organization_name,
                abbreviation=organization_abbreviation,
                reg_number=organization_reg_number,
                user_id=current_user.id
            )

            try:
                db.session.add(new_organization)
                db.session.commit()
                return redirect(url_for('index'))
            except Exception as e:
                return render_template('index.html', organizations=Organization.query.all(), error='There was an issue adding your organization')
        else:
            return render_template('index.html', organizations=Organization.query.all(), error='All fields are required')
    else:
        organizations = Organization.query.order_by(Organization.reg_number).all()
        return render_template("index.html", organizations=organizations)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    organization_to_delete = Organization.query.get_or_404(id)

    if organization_to_delete.user_id != current_user.id:
        flash("You do not have permission to delete this organization.", "danger")
        return redirect(url_for('index'))

    try:
        db.session.delete(organization_to_delete)
        db.session.commit()
        flash("Organization deleted successfully!", "success")
        return redirect(url_for('index'))
    except:
        flash("There was a problem deleting the organization.", "danger")
        return redirect(url_for('index'))

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    organization = Organization.query.get_or_404(id)

    if organization.user_id != current_user.id:
        flash("You do not have permission to update this organization.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        organization.name = request.form['name']
        organization.abbreviation = request.form['abbreviation']
        organization.reg_number = request.form['reg_number']
        try:
            db.session.commit()
            flash("Organization updated successfully!", "success")
            return redirect(url_for('index'))
        except:
            flash("There was an issue updating your organization", "danger")
            return redirect(url_for('index'))
    else:
        return render_template('update.html', organization=organization)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form['phone']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('This email is already registered. Please use a different email or log in.', 'email_error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, first_name=first_name, last_name=last_name, phone=phone)

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user) 
            flash('Registration successful! You are now logged in.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {e}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        current_user.email = request.form['email']
        current_user.phone = request.form.get('phone') 

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {e}', 'danger')
            return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('landing'))

if __name__ == "__main__":
    app.run(debug=True) 