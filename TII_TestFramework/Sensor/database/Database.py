import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")


from sqlalchemy.orm import DeclarativeMeta

import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from common.SingletonMeta import SingletonMeta
from sqlalchemy import create_engine


class Database(metaclass=SingletonMeta):
    __db_path__: str = '/home/andtokm/tmp/sensor.db'
    __base__: DeclarativeMeta = declarative_base()
    __engine__: sqlalchemy.engine = None

    def __init__(self):
        if not self.__engine__:
            self.__engine__ = create_engine(f'sqlite:///{self.__db_path__}')

    @property
    def base(self) -> DeclarativeMeta:
        return self.__base__

    @property
    def engine(self) -> sqlalchemy.engine:
        return self.__engine__

