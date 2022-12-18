from collections import defaultdict

import numpy as np
from typing import Dict
from vtkmodules.vtkCommonMath import vtkMatrix4x4


class ToothTransformation(object):
    angulationMatrix: vtkMatrix4x4 = vtkMatrix4x4()
    torksMatrix: vtkMatrix4x4 = vtkMatrix4x4()
    extrusionMatrix: vtkMatrix4x4 = vtkMatrix4x4()
    curveSetUp: vtkMatrix4x4 = vtkMatrix4x4()
    finalMatrix: vtkMatrix4x4 = vtkMatrix4x4()


class TransformationData(object):
    plane: np.ndarray = np.zeros(3, float)
    teethTransform: Dict[int, ToothTransformation] = defaultdict(ToothTransformation)