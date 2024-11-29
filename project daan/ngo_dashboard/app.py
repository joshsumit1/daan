from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField
from wtforms.validators import InputRequired, Email, Length, NumberRange, EqualTo, DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


app = Flask(__name__)
app.secret_key = 'secret-key'  # Change this for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ngo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    ngo_certificate = db.Column(db.String(200), nullable=False)  # Stores certificate details


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    total_donations = db.Column(db.Float, default=0.0)
    contributors = db.Column(db.Integer, default=0)


class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Automatically adds timestamp


# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[
        InputRequired(),
        Length(min=6),
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField("Confirm Password")
    ngo_certificate = StringField("NGO Certificate", validators=[InputRequired()])
    submit = SubmitField("Register")


class DonorRegisterForm(FlaskForm):
    name = StringField("Full Name", validators=[InputRequired(), Length(min=3, max=100)])
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField("Register as Donor")


class DonationForm(FlaskForm):
    campaign_id = StringField("Campaign ID", validators=[InputRequired()])
    amount = FloatField("Donation Amount", validators=[InputRequired(), NumberRange(min=1)])
    submit = SubmitField("Donate")


class Donor(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    total_donated = db.Column(db.Float, default=0.0)  # Total donations made by the donor


# Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard')
@login_required
def dashboard():
    campaigns = Campaign.query.all()
    total_donations = sum(c.total_donations for c in campaigns)
    total_contributors = sum(c.contributors for c in campaigns)
    return render_template('dashboard.html', campaigns=campaigns, total_donations=total_donations, total_contributors=total_contributors)


@app.route('/login_ngo', methods=['GET', 'POST'])
def ngo_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Search for the NGO by email in the database
        ngo = User.query.filter_by(email=email).first()

        if ngo and check_password_hash(ngo.password, password):
            login_user(ngo)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard page
        else:
            flash('Invalid credentials, please try again.', 'danger')

    return render_template('login_ngo.html')  # The login form page


@app.route('/register_ngo', methods=['GET', 'POST'])
def ngo_register():
    form = RegisterForm()
    if form.validate_on_submit():
        ngo_name = form.email.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm.data

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('ngo_register'))

        # Hash the password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')


        # Create the new NGO user
        new_ngo = User(
            email=email,
            password=hashed_password,
            ngo_certificate=form.ngo_certificate.data
        )

        db.session.add(new_ngo)
        db.session.commit()

        flash(f"Registration successful for {ngo_name}!", "success")
        return redirect(url_for('home'))

    return render_template('register_ngo.html', form=form)


@app.route('/donate', methods=['GET', 'POST'])
@login_required
def donate():
    form = DonationForm()
    campaigns = Campaign.query.all()  # Fetch all campaigns
    if form.validate_on_submit():
        campaign = Campaign.query.get(int(form.campaign_id.data))
        if campaign:
            campaign.total_donations += form.amount.data
            campaign.contributors += 1
            db.session.add(Donation(campaign_id=campaign.id, amount=form.amount.data))
            db.session.commit()
            flash("Donation successful", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Campaign ID", "error")
    return render_template('donation_form.html', form=form, campaigns=campaigns)


@app.route('/reports')
@login_required
def reports():
    donations = Donation.query.all()
    for donation in donations:
        donation.campaign = Campaign.query.get(donation.campaign_id)  # Get campaign details
    return render_template('reports.html', donations=donations)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))


@app.route('/register_donor', methods=['GET', 'POST'])
def register_donor():
    form = DonorRegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        
        new_donor = Donor(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password
        )
        
        db.session.add(new_donor)
        db.session.commit()

        flash("Donor registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register_donor.html', form=form)


@app.route('/donor_dashboard')
@login_required
def donor_dashboard():
    if not isinstance(current_user, Donor):
        flash("You are not authorized to access this page.", "error")
        return redirect(url_for('login'))

    total_donated = current_user.total_donated
    campaigns = Campaign.query.all()
    return render_template('donor_dashboard.html', total_donated=total_donated, campaigns=campaigns)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
