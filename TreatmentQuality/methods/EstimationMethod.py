import logging

from abc import ABC, abstractmethod
from typing import Dict, List
from vtkmodules.vtkCommonDataModel import vtkPolyData
from TreatmentQuality.utils.Utilities import Utilities

class EstimationMethod(ABC):
    UPPER_INCISORS = {12, 11, 21, 22}

    def __init__(self):
        self.logger = logging.getLogger("Logger")

    """
    abstract method for calculating/estimation biometric parameters of jaw models
    """
    @abstractmethod
    def estimate(self,
                 teeth_data_map: Dict[int, vtkPolyData],
                 contact_points: Dict,
                 teeth_lengths: Dict) -> Dict:
        pass

    """
    # TODO: add description
    """
    @property
    @abstractmethod
    def name(self):
        pass


    """
    # TODO: add description
    """
    def get_missing_teeth(self) -> Dict:
        pass

    """
    # TODO: add description
    """
    def get_incisors_length(self,
                            teeth_lengths: Dict) -> float:
        return sum([teeth_lengths[tooth_id] for tooth_id in self.UPPER_INCISORS])


    """
    # TODO: add description
    """
    @staticmethod
    def distance_between_two_points(pt1: List[float],
                                    pt2: List[float]) -> float:
        return Utilities.distance_between_two_points(pt1, pt2)