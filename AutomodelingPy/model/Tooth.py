import numpy as np
from vtkmodules.vtkCommonDataModel import vtkPolyData


class Tooth(object):
    # Mesiodistal params:
    width: float = 0.0

    def __init__(self,
                 tooth_id: int = 0,
                 data: vtkPolyData = None,
                 axisX: np.ndarray = None,
                 axisZ: np.ndarray = None,
                 axisY: np.ndarray = None) -> None:
        self.tooth_id: int = tooth_id
        self.data: vtkPolyData = data
        self.xAxis = axisX
        self.zAxis = axisZ
        self.yAxis = axisY

    def getCenter(self) -> np.ndarray:
        return np.asarray(self.data.GetCenter())

    def getBounds(self) -> np.ndarray:
        return np.asarray(self.data.GetBounds())

    def __repr__(self):
        return f'Tooth(id: {self.tooth_id})'

    def __str__(self):
        return f'Tooth(id: {self.tooth_id})'

    def copy(self):
        tooth: Tooth = Tooth(self.tooth_id, vtkPolyData(), self.xAxis.copy(), self.zAxis.copy(), self.yAxis.copy())
        tooth.data.DeepCopy(self.data)
        tooth.width = self.width
        return tooth

