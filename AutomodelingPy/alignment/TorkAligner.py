import math
import numpy as np

from abc import abstractmethod
from typing import Dict, List, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonMath import vtkMatrix4x4
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersGeneral import vtkTransformPolyDataFilter
from vtkmodules.vtkRenderingCore import vtkActor

from AutomodelingPy.estimation.Estimator import Estimator
from AutomodelingPy.model.FDI import FDI
from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Utilities import Utilities
from AutomodelingPy.utils.Transformation import TransformationData


class TorkAligner(object):
    LOWER_TEETH: List[int] = [47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37]

    @staticmethod
    def apply_tork(tooth: Tooth, x_angle) -> vtkMatrix4x4:
        center = tooth.getCenter()

        transformer: vtkTransform = vtkTransform()
        transformer.PostMultiply()
        transformer.Translate(-center)
        transformer.RotateWXYZ(x_angle, tooth.xAxis)
        transformer.Translate(center)

        matrix: np.ndarray = Utilities.vtkMatrixToNumpy(transformer.GetMatrix()).T

        transform_filter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transform_filter.SetInputData(tooth.data)
        transform_filter.SetTransform(transformer)
        transform_filter.Update()

        tooth.data = transform_filter.GetOutput()
        tooth.xAxis = np.matmul(tooth.xAxis, matrix)
        tooth.yAxis = np.matmul(tooth.yAxis, matrix)
        tooth.zAxis = np.matmul(tooth.zAxis, matrix)

        return transformer.GetMatrix()

    @staticmethod
    def get_angle(tooth: Tooth) -> float:
        z_axis_projection = tooth.zAxis * [1, 0, 1]
        x_angle = Utilities.angle_between_vectors(tooth.zAxis, z_axis_projection)
        x_angle *= -1 if tooth.zAxis[1] > 0 else 1
        return x_angle

    def align(self, teeth: Dict[int, Tooth],
              transformation: TransformationData):
        angles: Dict[int, float] = dict()
        for tooth_id in TorkAligner.LOWER_TEETH:
            tooth: Tooth = teeth.get(tooth_id)
            angles[tooth_id] = TorkAligner.get_angle(tooth)

            # print(f'--------------------------------- {tooth_id} ---------------------------- ')
            # print(tooth.zAxis)
            # print(f'Angle: {angles[tooth_id]}')

        # for simplicity, let's make them equal to the minimum value of the pair for now
        '''
        for id1, id2 in [[41, 31], [42, 32], [43, 33], [44, 34], [45, 35]]:
            angle: float = max(angles[id1], angles[id2])
            TorkAligner.apply_tork(teeth[id1], angles[id1] - angle)
            TorkAligner.apply_tork(teeth[id2], angles[id2] - angle)
        '''

        targetAngle: float = 0.0
        anglesToAppy: Dict[int, float] = dict()
        limits: List[float] = [9.27, 11.94, 14.61]

        if angles[31] > limits[1] and angles[41] > limits[1]:
            if limits[2] > angles[31] and limits[2] > angles[41]:
                targetAngle = max(angles[31], angles[41])
            else:
                targetAngle = limits[2]
        else:
            pass

        anglesToAppy[31] = targetAngle - angles[31]
        anglesToAppy[41] = targetAngle - angles[41]

        targetAngle -= 3

        anglesToAppy[32] = targetAngle - angles[32]
        anglesToAppy[42] = targetAngle - angles[42]

        targetAngle -= 3

        anglesToAppy[33] = targetAngle - angles[33]
        anglesToAppy[43] = targetAngle - angles[43]

        for id1, id2 in [[41, 31], [42, 32], [43, 33]]:
            angle: float = max(angles[id1], angles[id2])
            transformation.teethTransform[id1].torksMatrix = TorkAligner.apply_tork(teeth[id1], angles[id1] - angle)
            transformation.teethTransform[id2].torksMatrix = TorkAligner.apply_tork(teeth[id2], angles[id2] - angle)
