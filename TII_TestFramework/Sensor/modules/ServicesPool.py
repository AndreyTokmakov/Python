from __future__ import annotations

import os
import sys  # TODO: Remove it
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + "/..")

from typing import Dict
from common.SingletonMeta import SingletonMeta

"""
TODO: Add descriptions
"""


class ServicesPool(metaclass=SingletonMeta):
    instance: ServicesPool = None
    _services: Dict = dict()

    # CAPACITY: int = 4

    def __init__(self) -> None:
        pass

    @property
    def services(self) -> Dict:
        return self._services
