import sqlalchemy
from flask_security import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.future import Engine
from sqlalchemy.orm import Session

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


CONNECT_STRING = 'mysql+pymysql://dcube:YzqmVQt9@0.0.0.0:3306/dcube'
engine: Engine = sqlalchemy.create_engine(CONNECT_STRING)


def select_all_users():
    session = Session(bind=engine)
    for user in session.query(User).order_by(User.id):
        print(user)


if __name__ == '__main__':
    select_all_users()

