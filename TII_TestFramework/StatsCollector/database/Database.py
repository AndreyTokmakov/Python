from __future__ import annotations

import os
import sys  # TODO: Remove it

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")     # REMOVE
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/../..")  # REMOVE

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeMeta, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import database_exists, create_database

from common.SingletonMeta import SingletonMeta


class Database(metaclass=SingletonMeta):
    __db_path__: str = '/tmp/stats_collector.db'
    __base__: DeclarativeMeta = declarative_base()
    __engine__: sqlalchemy.engine = None

    def __init__(self):
        if not self.__engine__:
            self.__engine__ = create_engine(self.url)

    @property
    def base(self) -> DeclarativeMeta:
        return self.__base__

    @property
    def engine(self) -> sqlalchemy.engine:
        return self.__engine__

    @property
    def url(self) -> str:
        return f'sqlite:///{self.__db_path__}'

    # TODO: Add descriptions
    def exists(self) -> bool:
        return database_exists(self.url)

    @staticmethod
    def validate(database: Database) -> bool:
        if not database.exists():
            # TODO: Add logger
            print("DB do not exist. Creating")
            try:
                database.base.metadata.create_all(database.engine)
            except Exception as exc:
                # TODO: Add logger
                print(exc)
                return False

        return True
