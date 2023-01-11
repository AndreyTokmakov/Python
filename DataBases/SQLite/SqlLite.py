import sqlite3


def create_table():
    conn = sqlite3.connect('my_database.sqlite')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE SCHOOL
             (ID INT PRIMARY KEY     NOT NULL,
             NAME           TEXT    NOT NULL,
             AGE            INT     NOT NULL,
             ADDRESS        CHAR(50),
             MARKS          INT);''')
    cursor.close()


def insert_data():
    conn = sqlite3.connect('my_database.sqlite')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO SCHOOL (ID,NAME,AGE,ADDRESS,MARKS) VALUES (1, 'Rohan', 14, 'Delhi', 200)")
    cursor.execute("INSERT INTO SCHOOL (ID,NAME,AGE,ADDRESS,MARKS) VALUES (2, 'Allen', 14, 'Bangalore', 150 )")
    cursor.execute("INSERT INTO SCHOOL (ID,NAME,AGE,ADDRESS,MARKS) VALUES (3, 'Martha', 15, 'Hyderabad', 200 )")
    cursor.execute("INSERT INTO SCHOOL (ID,NAME,AGE,ADDRESS,MARKS) VALUES (4, 'Palak', 15, 'Kolkata', 650)")
    conn.commit()
    conn.close()


def insert_data_2():
    with sqlite3.connect('my_database.sqlite') as session:
        cursor = session.cursor()
        for i in range(10, 20):
            cursor.execute(f"INSERT INTO SCHOOL (ID,NAME,AGE,ADDRESS,MARKS) VALUES ({i}, 'Rohan', 14, 'Delhi', 200)")
            session.commit()


def select_data():
    conn = sqlite3.connect('my_database.sqlite')
    cursor = conn.cursor()
    for row in cursor.execute("SELECT id, name, marks from SCHOOL"):
        print("ID = ", row[0])

    print("NAME = ", row[1])
    print("MARKS = ", row[2], "\n")

    # conn.commit()
    conn.close()


if __name__ == '__main__':
    # create_table()
    insert_data()
    # select_data()
    # insert_data_2()
