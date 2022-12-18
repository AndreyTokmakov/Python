from __future__ import annotations

import sys  # TODO: Remove it
sys.path.append('/home/andtokm/DiskS/ProjectsUbuntu/Python/TII_TestFramework/Sensor')

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
