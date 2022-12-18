import math
import numpy as np

from typing import Dict, List
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersGeneral import vtkTransformPolyDataFilter

from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Utilities import Utilities
from AutomodelingPy.utils.Transformation import TransformationData, ToothTransformation


class AngulationAligner(object):
    LOWER_TEETH: List[int] = [44, 43, 42, 41, 31, 32, 33, 34]

    def __init__(self):
        pass

    @staticmethod
    def get_angle_Z(tooth: Tooth) -> float:
        tooth: Tooth = tooth.copy()

        directionX = 1 if tooth.xAxis[0] > 0 else -1
        point_horizontal = np.asarray([directionX, 0, 0])
        tooth.data = Utilities.setPolyDataCenter(tooth.data, 0, 0, 0)

        projection = tooth.xAxis * np.asarray([1, 0, 1])
        yRotateAngle = Utilities.angle_between_vectors(point_horizontal, projection)
        yRotateAngle *= -1 if projection[2] > point_horizontal[2] else 1
        yRotateAngle = (180 - yRotateAngle) if tooth.tooth_id in Utilities.UPPER_TEETH else yRotateAngle

        angle = np.deg2rad(yRotateAngle)
        sin, cos = math.sin(angle), math.cos(angle)
        M_Y = np.array([[cos,  0, sin],
                        [0,    1,   0],
                        [-sin, 0, cos]])

        tooth.data = Utilities.rotatePolyData(tooth.data, 0, yRotateAngle, 0)
        tooth.xAxis = np.matmul(tooth.xAxis, M_Y.T)
        tooth.yAxis = np.matmul(tooth.yAxis, M_Y.T)
        tooth.zAxis = np.matmul(tooth.zAxis, M_Y.T)

        projection = tooth.xAxis * np.asarray([1, 0, 1])
        zRotateAngle = Utilities.angle_between_vectors(tooth.xAxis, projection)
        zRotateAngle *= 1 if tooth.xAxis[1] > projection[1] else -1
        tooth.data = Utilities.rotatePolyData(tooth.data, 0, 0, zRotateAngle)

        sin, cos = math.sin(np.deg2rad(zRotateAngle)), math.cos(np.deg2rad(zRotateAngle))
        M_Z = np.array([[cos, -sin, 0],
                        [sin,  cos, 0],
                        [0,    0,   1]])

        tooth.xAxis = np.matmul(tooth.xAxis, M_Z.T)
        tooth.yAxis = np.matmul(tooth.yAxis, M_Z.T)
        tooth.zAxis = np.matmul(tooth.zAxis, M_Z.T)

        return zRotateAngle

    @staticmethod
    def get_angle_Z2(tooth: Tooth) -> float:
        tooth: Tooth = tooth.copy()

        x_axis_projection = tooth.xAxis * [1, 0, 1]
        z_angle = Utilities.angle_between_vectors(tooth.xAxis, x_axis_projection)
        z_angle *= 1 if tooth.xAxis[1] > x_axis_projection[1] else -1

        return z_angle

    @staticmethod
    def align(teeth: Dict[int, Tooth],
              transformation: TransformationData):
        for tooth_id in AngulationAligner.LOWER_TEETH:
            tooth: Tooth = teeth.get(tooth_id)
            center: np.ndarray = tooth.getCenter()
            zRotateAngle: float = AngulationAligner.get_angle_Z(tooth)

            transformer: vtkTransform = vtkTransform()
            transformer.PostMultiply()
            transformer.Translate(-center)
            transformer.RotateWXYZ(zRotateAngle, tooth.zAxis)
            transformer.Translate(center)

            transform_filter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
            transform_filter.SetInputData(tooth.data)
            transform_filter.SetTransform(transformer)
            transform_filter.Update()

            tooth.data = transform_filter.GetOutput()
            transformer.GetMatrix(transformation.teethTransform[tooth_id].angulationMatrix)
