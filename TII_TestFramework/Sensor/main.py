import sys  # TODO: Remove it
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

import time
from modules.Service import IService
from modules.Sensor import Sensor
from services.NetworkMonitor import NetworkMonitor
from services.DummyService import DummyService
from services.NotificationService import NotificationService



# TODO:
# 1. Daemon thread to watch started services
# 2. Service to dump stats to BD??
# 3. Service to send stats ???
# 4. WebGW - For Debug (configurable)
#    - Process: for web server
# 5. Database: SQLite

# TODO:
# 1. Add unit tests

# TODO:
# 1. Add logging (make it configurable)
# 2. Add exception handling

# TODO: Database
# 1. Validate DB at startup

if __name__ == '__main__':
    sensor: Sensor = Sensor()

    DummyService().start()
    NetworkMonitor().start()
    NotificationService().start()

    """
    while True:
        print(sensor.services_pool)
        print(sensor.services_pool.services)
        time.sleep(1)
    """