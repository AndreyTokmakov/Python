from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

tagging = db.Table('tagging',
                   db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
                   db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')))


class Tagging(db.Model):
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)
