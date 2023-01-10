import os
import sys  # TODO: Remove it

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")

import datetime
from sqlalchemy import select
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import Session

from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database

db: Database = Database()


def create_tables():
    # Base.metadata.create_all(engine)
    db: Database = Database()

    Database.validate(db)
    db.base.metadata.create_all(db.engine)
    pass


def validate_database():
    db.validate()


def insert_records():
    with Session(bind=db.engine) as session:
        stat1 = NetworkGeneral(total=4, tcp=2, icmp=1, udp=1)

        session.add_all([stat1])
        session.commit()


def insert_records_validate():
    Database.validate(db)

    with Session(bind=db.engine) as session:
        stat1 = NetworkGeneral(total=4, tcp=2, icmp=1, udp=1)
        session.add_all([stat1])
        session.commit()


def select_test():
    with Session(bind=db.engine) as session:
        for stat in session.query(NetworkGeneral).order_by(NetworkGeneral.timestamp):
            print(stat)


def select_last():
    with Session(bind=db.engine) as session:
        last = session.query(NetworkGeneral).order_by(NetworkGeneral.timestamp.desc()).first()
        print('NetworkStats ['
              f'\n\tpackets_total: {last.total}'
              f'\n\ticmp_packets: {last.icmp}'
              f'\n\ttcp_packets: {last.tcp}'
              f'\n\tudp_packets: {last.udp}'
              '\n]')


def select_where():
    with Session(bind=db.engine) as session:
        stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.icmp > 0)
        result = session.execute(stmt)
        for entry in result.fetchall():
            print(entry)


def select_where_LIMIT():
    with Session(bind=db.engine) as session:
        stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.icmp > 0).limit(1)
        result = session.execute(stmt)
        for entry in result.fetchall():
            print(entry)


def select_where_blocks():
    BLOCK_SIZE: int = 5
    table = []
    start_from: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

    with Session(bind=db.engine) as session:
        count: int = 1
        while count > 0:
            stmt = select([NetworkGeneral.__table__]).where(NetworkGeneral.timestamp > start_from) \
                .limit(BLOCK_SIZE).order_by(NetworkGeneral.timestamp)
            result = session.execute(stmt)
            result_set = result.fetchall()
            count = len(result_set)

            # print(f'--------------- {count} ----------------')
            for entry in result_set:
                table.append(entry)
                print(entry)

            start_from = table[-1].timestamp


if __name__ == '__main__':
    # create_tables()

    # validate_database()

    # insert_records()
    insert_records_validate()

    # select_test()
    # select_last()
    # select_where()
    # select_where_LIMIT()
    # select_where_blocks()

    # print(datetime.datetime.utcnow())
    # print(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc))

    pass
