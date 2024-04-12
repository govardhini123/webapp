from flask import Flask,render_template, url_for, request, redirect,Response,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt=Bcrypt(app)
socketio = SocketIO(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
    InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
    InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self,username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))


    return render_template('register.html', form=form)

@ app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@ app.route('/logout', methods=['GET', 'POST'])
def logout():
    return redirect(url_for('login'))


@ app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    sensor_clicked = True
    return render_template('dashboard.html', sensor_clicked=sensor_clicked )

latest_sensor_data = {"temperature": 0, "humidity": 0, "lux_value": 0, "accelerometer_data":0, "gyro_data":0}

@app.route('/update_sensor_data', methods=['POST'])
def update_sensor_data():
    data = request.get_json()
    temperature = data.get('temperature')
    humidity = data.get('humidity')
    latest_sensor_data['temperature'] = temperature
    latest_sensor_data['humidity'] = humidity
    return "Data received successfully"

@app.route('/update_light_intensity', methods=['POST'])
def update_light_intensity():
    data = request.get_json()
    lux_value = data.get('lux_value')
    latest_sensor_data['lux_value'] = lux_value
    return "Light intensity data received successfully"

@app.route('/update_MPU6050', methods=['POST'])
def update_MPU6050():
    data = request.get_json()
    accelerometer_data = data.get('accelerometer_data')
    gyro_data= data.get('gyro_data')
    print("Received Accelerometer Data:", accelerometer_data)
    print("Received Gyroscope Data:", gyro_data)
    latest_sensor_data['accelerometer_data'] = accelerometer_data
    latest_sensor_data['gyro_data'] = gyro_data
    return "MPU6050 data received successfully"

@app.route('/display_sensor_data', methods=['GET', 'POST'])
def display_sensor_data():
    return render_template("sensor.html", temperature=latest_sensor_data['temperature'], humidity=latest_sensor_data['humidity'])

@app.route('/display_light_sensor_data', methods=['GET', 'POST'])
def display_light_sensor_data():
    return render_template("light_sensor.html", lux_value=latest_sensor_data['lux_value'])


@app.route('/display_MPU_sensor_data', methods=['GET', 'POST'])
def display_MPU_sensor_data():
    return render_template("mpu_sensor.html", accelerometer_data=latest_sensor_data['accelerometer_data'], gyro_data=latest_sensor_data['gyro_data'])


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)
                                                   