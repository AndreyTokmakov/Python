from utilities.DbModelStatsConverter import DbModelStatsConverter
from database.Database import Database
from modules.Sensor import Sensor
from services.NetworkMonitor import NetworkMonitor
from services.NotificationService import NotificationService
from tests.FlaskTests.Test1.main import run_test_server


# TODO:
# 1. Daemon thread to watch started services
# 2. Service to dump stats to BD??
# 3. Service to send stats ???
# 4. WebGW - For Debug (configurable)
#    - Process: for web server
# 5. Database: SQLite

# TODO: Testing
# 1. Add unit tests

# TODO: Logging
# 1. Add logging (make it configurable)
# 2. Add exception handling

# TODO: Database
# 1. Validate DB at startup

# TODO: COnfiguration
# 1. IP address
# 2. Server Adress
# 3. ????

def start_up():
    if getattr(start_up, 'has_run', False):
        return
    start_up.has_run = True

    db: Database = Database()
    Database.validate(db)


if __name__ == '__main__':
    # Check DB and etc
    # TODO: Handle failures???
    start_up()

    sensor: Sensor = Sensor()

    # DummyService().start()
    NetworkMonitor().start()
    NotificationService().start()

    # run_test_server()
