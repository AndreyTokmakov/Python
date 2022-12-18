from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import joinedload

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/my_test_1.db'
db = SQLAlchemy(app)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Category %r>' % self.name


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    body = db.Column(db.Text, nullable=False)
    pub_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('posts', lazy=True))

    def __repr__(self):
        return '<Post %r>' % self.title


def creaate_and_write():
    with app.app_context():
        db.create_all()

        py = Category(name='Python')

        Post(title='Hello Python!', body='Python is pretty cool', category=py)
        p = Post(title='Snakes', body='Ssssssss')

        py.posts.append(p)
        db.session.add(py)
        db.session.commit()


def read_data():
    with app.app_context():
        query = Category.query.options(joinedload('posts'))
        for category in query:
            print(category, category.posts)


if __name__ == '__main__':
    # creaate_and_write()
    read_data()
