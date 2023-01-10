
import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")


from sqlalchemy import Integer, Column, DateTime, func
from database.Database import Database


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
