
import datetime
from sqlalchemy import select
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import Session
from sqlalchemy import Integer, String, Column, DateTime, func

from DataBases.SQLite.common.Database import Database

db: Database = Database()


class NetworkGeneral(Database().base):
    __tablename__ = 'network_general'

    # id = Column(Integer, primary_key=True)
    # dt = Column(DateTime(timezone=True), default=func.now())
    # timestamp = Column(DateTime, default=datetime.datetime.utcnow, primary_key=True)

    timestamp = Column(DateTime, primary_key=True)
    total = Column(Integer)
    icmp = Column(Integer)
    tcp = Column(Integer)
    udp = Column(Integer)

    def __repr__(self):
        return f'NetworkGeneral[{self.timestamp, self.total, self.icmp, self.tcp, self.udp}]'


def insert_records_validate():
    Database.validate(db)

    with Session(bind=db.engine) as session:
        stat1 = NetworkGeneral(timestamp=datetime.datetime.utcnow(), total=4, tcp=2, icmp=1, udp=33)
        session.add_all([stat1])
        session.commit()


if __name__ == '__main__':
    # insert_records_validate()

    # print(datetime.datetime.utcnow())
    print(type(datetime.datetime.utcnow()))

