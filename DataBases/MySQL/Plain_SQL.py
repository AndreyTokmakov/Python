from mysql.connector import connect, Error


class AuthData(object):
    # user: str = 'admin'
    # password: str = 'qwerty12345'
    # db: str = 'testdb'

    user: str = 'dcube'
    password: str = 'YzqmVQt9'
    db: str = 'dcube'


def connect_to_database():
    with connect(host='127.0.0.1',
                 database=AuthData.db,
                 user=AuthData.user,
                 password=AuthData.password) as conn:
        cursor = conn.cursor()


def show_databases():
    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:
        my_cursor = connection.cursor()
        my_cursor.execute("SHOW DATABASES")
        for x in my_cursor:
            print(x)


def show_tables():
    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:
        my_cursor = connection.cursor()
        my_cursor.execute("SHOW TABLES")
        for x in my_cursor:
            print(x)


def create_database():
    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:
        cursor = connection.cursor()
        cursor.execute("CREATE DATABASE testdb2")


def create_table():
    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE demo (name VARCHAR(255), id INT)")


def insert():
    sql = "INSERT INTO demo (name, id) VALUES (%s, %s)"
    val = ("John", "21")

    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:

        cursor = connection.cursor()
        try:
            cursor.execute(sql, val)
            connection.commit()
        except:
            connection.rollback()


def insert_many():
    sql = "INSERT INTO demo (name, id) VALUES (%s, %s)"
    val = [ ('Peter', '4'), ('Amy', '652'), ('Hannah', '21'), ('Michael', '345'), ('Sandy', '2') ]

    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:

        cursor = connection.cursor()
        try:
            cursor.executemany(sql, val)
            connection.commit()
        except:
            connection.rollback()


def select():
    with connect(host='127.0.0.1', database=AuthData.db,
                 user=AuthData.user, password=AuthData.password) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM demo")
        for x in cursor.fetchall():
            print(x)


if __name__ == '__main__':
    # connect_to_database()

    show_databases()
    # show_tables()

    # create_database()
    # create_table()

    # insert()
    # insert_many()
    # select()

    pass
