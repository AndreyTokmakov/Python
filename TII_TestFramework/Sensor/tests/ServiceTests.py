
import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")

import time
from modules.Service import IService
from modules.ServicesPool import ServicesPool


class NetworkMonitor(IService):

    def handler(self) -> bool:
        for i in range(3):
            print(f'{self}: {i}')
            time.sleep(0.5)
        return True


class FilesystemMonitor(IService):

    def handler(self) -> bool:
        for i in range(3):
            print(f'{self}: {i}')
            time.sleep(0.5)
        return True


class Tests(object):

    @staticmethod
    def run_services():
        pool = ServicesPool()
        print(len(pool.services))

        service = NetworkMonitor()
        service.start()

        print(len(pool.services))
        service.wait()
        print(len(pool.services))

        service = FilesystemMonitor()
        service.start()

        service.wait()
        print(len(pool.services))


    @staticmethod
    def check_pool_is_single_instance():
        pool1 = ServicesPool()
        pool2 = ServicesPool()

        print(pool1 == pool2)
        print(pool1 is pool2)


if __name__ == '__main__':
    # Tests.run_services()
    Tests.check_pool_is_single_instance()