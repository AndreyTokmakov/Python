
import sys  # TODO: Remove it
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

import time
from modules.Service import IService
from multiprocessing import Process, Lock


class ServiceOne(IService):

    def __init__(self, lock: Lock):
        IService.__init__(self)
        self.lock: Lock = lock

    def handler(self) -> bool:
        print(f'{self} started')
        for i in range(10):
            with self.lock:
                print(f'{self}: {i}')
            time.sleep(1)
        return True


class ServiceTwo(IService):

    def __init__(self, lock: Lock):
        IService.__init__(self)
        self.lock: Lock = lock

    def handler(self) -> bool:
        print(f'{self} started')
        for i in range(10):
            with self.lock:
                print(f'{self}: {i}')
            time.sleep(0.5)
        return True


if __name__ == '__main__':
    # create the shared lock
    lock = Lock()

    service1, service2 = ServiceOne(lock), ServiceTwo(lock)
    service1.start()
    service2.start()