import sqlalchemy as db
from sqlalchemy import create_engine, String, Text, ForeignKey
from sqlalchemy import MetaData, Table, Column, Integer, ARRAY
from sqlalchemy.orm import Session
from sqlalchemy import Table, Index, Integer, String, Column, Text, \
    DateTime, Boolean, PrimaryKeyConstraint, \
    UniqueConstraint, ForeignKeyConstraint
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

DB_PATH: str = '/home/andtokm/DiskS/Temp/my_test2.db'

engine: db.engine = create_engine(f'sqlite:///{DB_PATH}')
'''
engine = create_engine(f'sqlite:///{DB_PATH}', echo=True, pool_size=6, max_overflow=10, encoding='latin1')
'''


Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    # last_name = Column(String(100), nullable=False)

    def __repr__(self):
        return f'User[{self.id, self.name}]'


# https://pythonru.com/biblioteki/shemy-sqlalchemy-core
# https://pythonru.com/biblioteki/crud-sqlalchemy-orm
def create():
    engine.connect()
    metadata = MetaData()
    # shows = db.Table('Shows', metadata, autoload=True, autoload_with=engine)

    user = Table('users', metadata,
                 Column('id', Integer(), primary_key=True),
                 Column('name', String(200), nullable=False), )

    posts = Table('posts', metadata,
                  Column('id', Integer(), primary_key=True),
                  Column('post_title', String(200), nullable=False),
                  Column('post_slug', String(200), nullable=False),
                  Column('content', Text(), nullable=False),
                  Column('user_id', ForeignKey("users.id")), )

    metadata.create_all(engine)


def add():
    session = Session(bind=engine)

    user = User(id=1, name="User1")

    session.add_all([user])
    session.commit()


def select():
    session = Session(bind=engine)

    result = (
        session.query(User).filter_by(name="User1").first()
    )

    print(result)


def select_all_users():
    session = Session(bind=engine)

    for instance in session.query(User).order_by(User.id):
        print(instance.id, instance.name)

    print()

    for id, name in session.query(User.id, User.name):
        print(id, name)

    print()

    for row in session.query(User, User.name).all():
        print(row.User, row.name)

    session.close()


if __name__ == '__main__':
    # create()

    # add()

    # select()
    select_all_users()

    pass
