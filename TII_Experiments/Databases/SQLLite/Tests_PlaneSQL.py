import sqlite3

DB_PATH: str = '/home/andtokm/DiskS/Temp/my_test2.db'


def create():
    connection: sqlite3.Connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE movie(title, year, score)")
    cursor.execute(
        """
        INSERT INTO movie VALUES
            ('Monty Python and the Holy Grail', 1975, 8.2),
            ('And Now for Something Completely Different', 1971, 7.5);
        """
    )
    connection.commit()


def select():
    connection: sqlite3.Connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    res = cursor.execute("SELECT title FROM movie")

    print(res.fetchone())


def select2():
    connection: sqlite3.Connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    for row in cursor.execute("SELECT * FROM movie"):
        print(row)


def select_Test():
    connection: sqlite3.Connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    for row in cursor.execute("SELECT * FROM users"):
        print(row)


if __name__ == '__main__':
    # create()
    # select()
    # select2()
    select_Test()
    pass


