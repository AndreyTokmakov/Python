from __future__ import annotations

import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")


import time
from threading import Thread

from modules.ServicesPool import ServicesPool
from common.SingletonMeta import SingletonMeta


# TODO:
# 1. Daemon thread to watch started services
# 2. Service to dump stats to BD??
# 3. Service to send stats ???
# 4. WebGW - For Debug (configurable)
#    - Process: for web server
# 5. Database: SQLite

# TODO:
# 1. Add unit tests

class Sensor(metaclass=SingletonMeta):

    def __init__(self):
        self.services_pool: ServicesPool = ServicesPool()

        # TODO: Shall we make it Service
        # NOTE: Running 'watch_dog' as a process we lose access to 'services_pool' from the main thread
        # self.watch_dog: Process = Process(target = self.__watch_dog, name = "WatchDog")
        # self.watch_dog: Thread = Thread(target=self.__watch_dog, args=())
        # self.watch_dog.start()

    def __watch_dog(self) -> None:
        while True:
            print(self.services_pool.services)
            time.sleep(1)
