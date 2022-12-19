import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../../..")


import datetime
import threading
import time

from sqlalchemy import select

from flask import Flask, Markup, render_template
from sqlalchemy.orm import Session
from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database

db: Database = Database()
BLOCK_SIZE: int = 5
table = []

X = [
    'JAN', 'FEB', 'MAR', 'APR',
    'MAY', 'JUN', 'JUL', 'AUG',
    'SEP', 'OCT', 'NOV', 'DEC'
]

Y = [
    967.67, 1190.89, 1079.75, 1349.19,
    2328.91, 2504.28, 2873.83, 4764.87,
    4349.29, 6458.30, 9907, 16297
]


def read_database():
    start_from: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

    global table
    with Session(bind=db.engine) as session:
        # count: int = 1
        while True:
            stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.timestamp > start_from) \
                .limit(BLOCK_SIZE).order_by(NetworkGeneral.timestamp)
            result = session.execute(stmt)
            result_set = result.fetchall()
            # count = len(result_set)

            # print(f'--------------- {count} {len(table)}  ----------------')
            for entry in result_set:
                table.append(entry)
                # print(entry)

            start_from = table[-1].timestamp
            time.sleep(1)


app = Flask(__name__)


@app.route('/')
def line():
    values, timestamp = [], []
    for entry in table:
    # for x, y in zip(Y, X):
        values.append(entry.total)
        timestamp.append(entry.timestamp)

    return render_template('line_chart.html',
                           title='Sensor traffic monitoring',
                           max=max(values),
                           labels=timestamp,
                           values=values)


if __name__ == '__main__':
    reader: threading.Thread = threading.Thread(target=read_database, args=())
    reader.start()

    app.run(host='0.0.0.0', port=8080)
    reader.join()
