import sqlalchemy
import pymysql
from sqlalchemy.engine import CursorResult


# CONNECT_STRING = 'mysql://dcube:YzqmVQt9@0.0.0.0:3306/dcube'
CONNECT_STRING = 'mysql+pymysql://dcube:YzqmVQt9@0.0.0.0:3306/dcube'


def show_databases():
    engine = sqlalchemy.create_engine(CONNECT_STRING)

    # engine.execute("CREATE DATABASE dbname") #create db
    # engine.execute("USE dbname") # select new db

    databases: CursorResult = engine.execute("SHOW DATABASES;")
    for db in databases:
        print(db)


def show_users():
    engine = sqlalchemy.create_engine(CONNECT_STRING)

    users: CursorResult = engine.execute("SELECT * FROM dcube.user;")
    for user in users:
        print(user)


if __name__ == '__main__':
    # show_databases()
    show_users()

    pass
