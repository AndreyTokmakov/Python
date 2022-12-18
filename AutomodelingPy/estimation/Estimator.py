
from abc import ABC, abstractmethod
from typing import Dict

from AutomodelingPy.model.Tooth import Tooth


class Estimator(ABC):

    """
    abstract method for calculating/estimation biometric parameters for single tooth
    """
    @abstractmethod
    def estimate(self, tooth: Tooth) -> Dict:
        pass

    """
    # TODO: add description
    """
    @property
    @abstractmethod
    def name(self):
        pass