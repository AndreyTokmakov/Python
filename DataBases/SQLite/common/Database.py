from __future__ import annotations

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeMeta, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import database_exists, create_database

from DataBases.SQLite.common.SingletonMeta import SingletonMeta


class Database(metaclass=SingletonMeta):
    __db_path__: str = '/tmp/test_data_1.db'
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
