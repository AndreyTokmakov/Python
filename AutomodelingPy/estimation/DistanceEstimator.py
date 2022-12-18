import math
import numpy as np

from abc import abstractmethod
from typing import Dict
from vtkmodules.vtkCommonDataModel import vtkPolyData

from AutomodelingPy.estimation.Estimator import Estimator
from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Utilities import Utilities


class DistanceEstimator(Estimator):

    def __init__(self):
        super().__init__()

    """
    abstract method for calculating/estimation biometric parameters for single tooth
    """

    def estimate(self, tooth: Tooth) -> None:
        toothData: vtkPolyData = self.orient_single_tooth(tooth)
        bounds: np.array = np.asarray(toothData.GetBounds())
        tooth.width = bounds[1] - bounds[0]

    """
    # TODO: add description
    """

    @property
    def name(self):
        return 'DistanceEstimator'

    """
    # TODO: add description
    """

    def orient_single_tooth(self, tooth: Tooth) -> vtkPolyData:
        # Orient the jaw horizontally:
        xAxis = tooth.xAxis

        directionX = 1 if xAxis[0] > 0 else -1
        point_horizontal = np.asarray([directionX, 0, 0])
        toothPolyData = Utilities.setPolyDataCenter(tooth.data, 0, 0, 0)

        projection = xAxis * np.asarray([1, 0, 1])
        yRotateAngle = Utilities.angle_between_vectors(point_horizontal, projection)
        yRotateAngle *= -1 if projection[2] > point_horizontal[2] else 1
        yRotateAngle = (180 - yRotateAngle) if tooth.tooth_id in Utilities.UPPER_TEETH else yRotateAngle

        angle = np.deg2rad(yRotateAngle)
        sin, cos = math.sin(angle), math.cos(angle)
        M_Y = np.array([[cos, 0, sin],
                        [0, 1, 0],
                        [-sin, 0, cos]])

        toothPolyData = Utilities.rotatePolyData(toothPolyData, 0, yRotateAngle, 0)
        xAxis = np.matmul(xAxis, M_Y.T)
        projection = xAxis * np.asarray([1, 0, 1])

        zRotateAngle = Utilities.angle_between_vectors(xAxis, projection)
        zRotateAngle *= 1 if xAxis[1] > projection[1] else -1

        return Utilities.rotatePolyData(toothPolyData, 0, 0, zRotateAngle)


'''
class DistanceEstimator(Estimator):

    def __init__(self):
        super().__init__()
        self.__matrix = Utilities.buildRotation_matrix_bad(90, 180, 0)
        self.__matrix = Utilities.vtkMatrixToNumpy(self.__matrix)

    """
    abstract method for calculating/estimation biometric parameters for single tooth
    """
    def estimate(self, tooth: Tooth) -> None:
        toothData: vtkPolyData = self.orient_single_tooth(tooth)
        bounds: np.array = np.asarray(toothData.GetBounds())
        tooth.width = bounds[1] - bounds[0]

        # t = Tooth(tooth.tooth_id, toothData, tooth.xAxis, tooth.zAxis, tooth.yAxis)
        # Utilities.DisplayToothWithAxes(t)
        Utilities.DisplayActors([Utilities.getPolyDataActor(toothData)])

    """
    # TODO: add description
    """
    @property
    def name(self):
        return 'DistanceEstimator'

    """
    # TODO: add description
    """
    def orient_single_tooth(self, tooth: Tooth) -> vtkPolyData:
        # Orient the jaw horizontally:
        toothPolyData: vtkPolyData = Utilities.rotatePolyData(tooth.data, 90, 180)
        xAxis = np.matmul(tooth.xAxis, self.__matrix)

        directionX = 1 if xAxis[0] > 0 else -1
        point_horizontal = np.asarray([directionX, 0, 0])
        toothPolyData = Utilities.setPolyDataCenter(toothPolyData, 0, 0, 0)

        projection = xAxis * np.asarray([1, 0, 1])
        yRotateAngle = Utilities.angle_between_vectors(point_horizontal, projection)
        yRotateAngle *= -1 if projection[2] > point_horizontal[2] else 1
        yRotateAngle = (180 - yRotateAngle) if tooth.tooth_id in Utilities.UPPER_TEETH else yRotateAngle

        angle = np.deg2rad(yRotateAngle)
        sin, cos = math.sin(angle), math.cos(angle)
        M_Y = np.array([[cos, 0, sin],
                        [0, 1, 0],
                        [-sin, 0, cos]])

        toothPolyData = Utilities.rotatePolyData(toothPolyData, 0, yRotateAngle, 0)
        xAxis = np.matmul(xAxis, M_Y.T)
        projection = xAxis * np.asarray([1, 0, 1])

        zRotateAngle = Utilities.angle_between_vectors(xAxis, projection)
        zRotateAngle *= 1 if xAxis[1] > projection[1] else -1

        return Utilities.rotatePolyData(toothPolyData, 0, 0, zRotateAngle)
'''
