from __future__ import annotations

import sys  # TODO: Remove it
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')


from abc import ABC, abstractmethod
from multiprocessing import Process
from modules.ServicesPool import ServicesPool


# NOTE: Make them singletons ???
#       Singletons with registration??
# TODO: Run in single process
# TODO: Report state
class IService(ABC):

    # Shall be shared among all IService subclasses
    __pool = ServicesPool()

    """
    FIXME: add detailed description
    1. name is set up to class name if not given
    """
    def __init__(self,
                 name: str = None) -> None:
        self.__proc = None
        self.__name: str = name if (None != name) else self.__class__.__name__

    """
    The method implements all the basic logic of the service or at least defines the input point to it
    It is the responsibility of the developer to provide a valid implementation of this method
    """
    @abstractmethod
    def handler(self) -> bool:
        """
        Shall be implemented in each IService subclass
        """
        raise Exception("Not implemented")


    """
    TODO: rename
    This method starts thread.
    Registers it
    """
    # FIXME: Return 'self' or 'bool' ???
    def start(self) -> IService:
        self.__proc: Process = Process(target=self.handler,
                                       name=self.name,
                                       args=())
        self.__proc.start()
        self.__pool.services[self.__proc.name] = self
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

