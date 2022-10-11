import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_email = request.form["email"]
        check_email_existing = User.query.filter_by(email=new_email).first()
        if check_email_existing:
            flash("You already signed up with that email, try logging in instead")
            return redirect("/login")
        new_name = request.form["name"]
        new_password = request.form["password"]
        hashed_password = werkzeug.security.generate_password_hash(new_password)
        new_user = User(email=new_email,
                        name=new_name,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template("secrets.html", name=new_name.title())
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form["email"]).first()
        if not user:
            flash("This email does not exist")
            return redirect("/login")
        if check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return render_template('secrets.html', name=user.name)
        else:
            flash("Invalid Password please try again")
            return redirect("/login")
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static', filename='files/cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=8000)
