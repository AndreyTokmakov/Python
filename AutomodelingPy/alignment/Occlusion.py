import math
import numpy as np

from scipy import stats
from typing import Dict, List

from AutomodelingPy.model.FDI import FDI
from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Transformation import TransformationData
from AutomodelingPy.utils.Utilities import Utilities


class Occlusion(object):

    def __init__(self):
        pass

    @staticmethod
    def __get_edge_points(teeth: Dict[int, Tooth]) -> List[np.ndarray]:
        points: List[np.ndarray] = []
        for _, tooth in teeth.items():
            center, bounds = tooth.getCenter(), tooth.getBounds()
            height: float = bounds[3] - bounds[2]
            center[1] += (height / 2 if FDI.isLowerTooth(tooth.tooth_id) else -height / 2)
            points.append(center)

        return points

    @staticmethod
    def orient_teeth(teeth: Dict[int, Tooth],
                     transformation: TransformationData) -> np.ndarray:

        pts: List[np.ndarray] = Occlusion.__get_edge_points(teeth)
        y, z = [pt[1] for pt in pts], [pt[2] for pt in pts]
        slope, intercept, *other = stats.linregress(z, y)

        angles: np.ndarray = transformation.plane
        angles[0] = math.atan(slope) * 180.0 / math.pi

        for _, tooth in teeth.items():
            tooth.data = Utilities.rotatePolyData(tooth.data, angles[0], 0, 0)

        pts = Occlusion.__get_edge_points(teeth)
        x, y = [pt[0] for pt in pts], [pt[1] for pt in pts]
        slope, intercept, *other = stats.linregress(x, y)
        angles[2] = math.atan(slope) * 180.0 / math.pi * -1.0

        sinX, sinZ = math.sin(np.deg2rad(angles[0])), math.sin(np.deg2rad(angles[2]))
        cosX, cosZ = math.cos(np.deg2rad(angles[0])), math.cos(np.deg2rad(angles[2]))
        matrix: np.ndarray = np.array([[1 * cosZ, -sinZ, 0],
                                       [cosX * sinZ, cosX * cosZ, -sinX],
                                       [sinX * sinZ, sinX * cosZ, cosX]])

        for _, tooth in teeth.items():
            tooth.data = Utilities.rotatePolyData(tooth.data, 0, 0, angles[2])
            tooth.xAxis = np.matmul(tooth.xAxis, matrix.T)
            tooth.yAxis = np.matmul(tooth.yAxis, matrix.T)
            tooth.zAxis = np.matmul(tooth.zAxis, matrix.T)

        return angles
