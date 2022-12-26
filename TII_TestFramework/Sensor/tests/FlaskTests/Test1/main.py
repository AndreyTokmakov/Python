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


class Context(object):
    BLOCK_SIZE: int = 5

    def __init__(self):
        self.database: Database = Database()
        self.table = []
        self.updater: threading.Thread = threading.Thread(target=self.read_database, args=())

    def read_database(self):
        start_from: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

        with Session(bind=self.database.engine) as session:
            while True:
                stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.timestamp > start_from) \
                    .limit(Context.BLOCK_SIZE).order_by(NetworkGeneral.timestamp)
                result = session.execute(stmt)
                result_set = result.fetchall()

                for entry in result_set:
                    self.table.append(entry)
                    start_from = entry.timestamp

                time.sleep(1)

    def start(self):
        self.updater.start()


app = Flask(__name__)
ctx = Context()


@app.route('/')
def line():
    timestamps = [x.timestamp for x in ctx.table]
    total = [y.total for y in ctx.table]
    tcp = [y.tcp for y in ctx.table]
    icmp = [y.icmp for y in ctx.table]
    udp = [y.udp for y in ctx.table]

    return render_template('dashboard.html',
                           total_values=total, total_timestamps=timestamps, total_legend="Packet total",
                           tcp_values=tcp, tcp_timestamps=timestamps, tcp_legend="TCP packet total",
                           icmp_values=icmp, icmp_timestamps=timestamps, icmp_legend="ICMP packet total",
                           udp_values=udp, udp_timestamps=timestamps, udp_legend="UDP packet total",
                           )


def run_test_server():
    ctx.start()
    app.run(host='0.0.0.0', port=5000)


if __name__ == '__main__':
    run_test_server()
