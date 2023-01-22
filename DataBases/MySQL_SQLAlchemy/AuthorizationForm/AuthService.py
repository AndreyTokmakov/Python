from flask import Flask
from flask_security import UserMixin, Security, SQLAlchemyUserDatastore, RoleMixin, LoginForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField
from wtforms.validators import InputRequired

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    api_key = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    # roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)

    def get_name(self):
        return self.username

    def __str__(self) -> str:
        return f'User[id: {self.id}, name: {self.username}, email: {self.email}, password: {self.password}]'


class Role(db.Model, RoleMixin):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)


CONNECT_STRING = 'mysql+pymysql://dcube:YzqmVQt9@0.0.0.0:3306/dcube'

flaskApp = Flask(__name__)
flaskApp.config['SQLALCHEMY_DATABASE_URI'] = CONNECT_STRING
flaskApp.config['SECRET_KEY'] = "random string"
flaskApp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)


class ExtendedLoginForm(LoginForm):
    email = StringField('Username', [InputRequired()])


if __name__ == '__main__':
    db.init_app(flaskApp)
    Security(flaskApp, user_datastore, login_form=ExtendedLoginForm)

    with flaskApp.app_context():
        flaskApp.run(debug=True)
