import math
import sys

import numpy as np

from abc import abstractmethod
from typing import Dict, List, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersGeneral import vtkTransformPolyDataFilter
from vtkmodules.vtkRenderingCore import vtkActor

from AutomodelingPy.estimation.Estimator import Estimator
from AutomodelingPy.model.FDI import FDI
from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Utilities import Utilities
from AutomodelingPy.utils.Transformation import TransformationData


class ExtrusionAligner(object):
    LOWER_TEETH: List[int] = [47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37]

    def __init__(self):
        pass

    @staticmethod
    def __get_edge_points(teeth: Dict[int, Tooth]) -> Dict[int, np.ndarray]:
        points: Dict[int, np.ndarray] = dict()
        for tooth_id, tooth in teeth.items():
            center, bounds = tooth.getCenter(), tooth.getBounds()
            height: float = bounds[3] - bounds[2]
            center[1] += (height / 2 if FDI.isLowerTooth(tooth.tooth_id) else -height / 2)
            points[tooth_id] = center

        return points

    @staticmethod
    def __get_control_tooth(pts: Dict[int, np.ndarray]) -> int:

        return 1

    def align(self,
              teeth: Dict[int, Tooth],
              transformation: TransformationData):
        pts: Dict[int, np.ndarray] = ExtrusionAligner.__get_edge_points(teeth)

        # pts[33][1] = 9

        # '''
        lower_teeth = [pd for tooth_id, pd in teeth.items() if tooth_id in Utilities.LOWER_TEETH]
        actors: List[vtkActor] = []
        for tooth in lower_teeth:
            actors.append(Utilities.getPolyDataActor(tooth.data))
            actors.append(Utilities.getPointsActor([pts[tooth.tooth_id]]))

        Utilities.DisplayActors(actors, windowName="ExtrusionAligner")
        # '''

        '''
        y_min: float = sys.float_info.max
        for tooth_id in Utilities.LOWER_TEETH:
            if tooth_id in pts.keys():
                pt = pts[tooth_id]
                y_min = min(pt[1], y_min)
                # print(f'{tooth_id} : {pt[1]}')
        '''
        # print(y_min)

        print(pts[37][1], pts[47][1])
        print(pts[33][1], pts[43][1])
        print(pts[31][1], pts[32][1], pts[41][1], pts[42][1])
















