import sys
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

import time

from modules.Service import IService, ServicesPool
from database.model.NetworkGeneral import NetworkGeneral
from database.Database import Database
from sqlalchemy.orm import Session


class NotificationService(IService):

    def __init__(self):
        IService.__init__(self)
        self.db: Database = Database()

    def handler(self) -> None:
        while True:
            with Session(bind=self.db.engine) as session:
                last = session.query(NetworkGeneral).order_by(NetworkGeneral.timestamp.desc()).first()
                print('NetworkStats ['
                      f'\n\tpackets_total: {last.total}'
                      f'\n\ticmp_packets: {last.icmp}'
                      f'\n\ttcp_packets: {last.tcp}'
                      f'\n\tudp_packets: {last.udp}'
                      '\n]')
                time.sleep(5)
