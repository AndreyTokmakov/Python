from __future__ import annotations

from abc import ABC, abstractmethod
from multiprocessing import Pool, Process
import time
from typing import Dict, List


class ServicesPool(object):
    instance: ServicesPool = None
    pool: Dict[str, IService] = dict()
    # __POOL_CAPACITY__: int = 4

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self):
        print("ServicesPool()")
        # self.pool = Pool(processes = ServicesPool.__POOL_CAPACITY__)


# NOTE: Make them singletons ???
#       Singletons with registration??
# TODO: Run in single process
# TODO: Report state
class IService(ABC):

    """
    FIXME: add detailed description
    1. name is set up to class name if not given
    """
    def __init__(self,
                 name: str = None) -> None:
        self.__services = ServicesPool()
        self.__proc = None
        self.__name: str = name if (None != name) else self.__class__.__name__

    """
    FIXME: rename
    The Creator class declares the factory method that is supposed to return an object of a Product class.
    The Creator's subclasses usually provide the implementation of this method.
    """
    @abstractmethod
    def handler(self) -> bool:
        """
        FIXME: rename. that the Creator may also provide some default implementation of the factory method.
        """
        raise Exception("Not implemented")


    """
    TODO: rename
    This method starts thread.
    Registers it
    """
    def start(self) -> IService:
        self.__proc: Process = Process(target=self.handler,
                                       name=self.name,
                                       args=())
        self.__proc.start()
        self.__services.pool[self.__proc.name] = self
        return self


    def wait(self, timeout_seconds: int = None) -> None:
        """
        Wait until child process terminates
        """
        self.__proc.join(timeout_seconds)


    @property
    def name(self) -> str:
        """
        Return the actual service name
        """
        return self.__name


    def __repr__(self) -> str:
        """
        Return the actual service name
        """
        return f'Service [{self.name}, pid: {self.__proc.pid}, running: {self.__proc.is_alive()}]'


class NetworkMonitor(IService):

    def handler(self) -> bool:
        for i in range(3):
            print(f'{self}: {i}')
            time.sleep(1)
        return True


class FilesystemMonitor(IService):

    def handler(self) -> bool:
        for i in range(3):
            print(f'{FilesystemMonitor}: {i}')
            time.sleep(1)
        return True


if __name__ == '__main__':

    '''service1 = NetworkMonitor()
    service2 = FilesystemMonitor()

    src1 = service1.run_service()
    src2 = service2.run_service()

    print(1)

    src1.wait()
    src2.wait()'''


    '''
    print(service1.services_pool == service2.services_pool)
    print(service1.services_pool is service2.services_pool)

    print(service1.services_pool.pool == service2.services_pool.pool)
    print(service1.services_pool.pool is service2.services_pool.pool)
    '''

    pool = ServicesPool()

    service1 = NetworkMonitor()
    srv: IService = service1.start()

    print(len(pool.pool))
    srv.wait()
    print(len(pool.pool))

    print(srv)