from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/my_test.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


# This will create Database in /tmp/my_test.db
def create_database():
    with app.app_context():
        db.create_all()


def create_users():
    with app.app_context():
        admin = User(username='admin', email='admin@example.com')
        guest = User(username='guest', email='guest@example.com')

        db.session.add(admin)
        db.session.add(guest)
        db.session.commit()


def read_data():
    with app.app_context():
        query_1 = User.query.all()
        print(query_1)

        query_2 = User.query.filter_by(username='admin').first()
        print(query_2)


if __name__ == '__main__':
    create_database()
    # create_users()
    # read_data()
