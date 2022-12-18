# noinspection PyUnresolvedReferences
from typing import Tuple
import numpy as np

import vtkmodules.vtkInteractionStyle
# noinspection PyUnresolvedReferences
import vtkmodules.vtkRenderingOpenGL2
from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkFiltersCore import vtkFeatureEdges
from vtkmodules.vtkFiltersModeling import vtkOutlineFilter
from vtkmodules.vtkFiltersSources import vtkDiskSource
from vtkmodules.vtkRenderingCore import (
    vtkActor,
    vtkPolyDataMapper,
    vtkRenderWindow,
    vtkRenderWindowInteractor,
    vtkRenderer
)

from VTK_Experiments.Utilities import Utilities


def Test():
    STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'
    polyData: vtkPolyData = Utilities.readStl(STL_FILE)

    ptCenter: np.array = np.asarray(polyData.GetCenter())
    bounds: np.array = np.asarray(polyData.GetBounds())

    xLength: float = bounds[1] - bounds[0]
    yLength: float = bounds[3] - bounds[2]
    zLength: float = bounds[5] - bounds[4]

    xLeftPoint: np.array = ptCenter - np.array([xLength / 2, 0, 0])
    xRightPoint: np.array = ptCenter + np.array([xLength / 2, 0, 0])

    yBottomPoint: np.array = ptCenter - np.array([0, yLength / 2, 0])
    yTopPoint: np.array = ptCenter + np.array([0, yLength / 2, 0])

    zFrontPoint: np.array = ptCenter - np.array([0, 0, zLength / 2])
    zBacktPoint: np.array = ptCenter + np.array([0, 0, zLength / 2])

    teethActor: vtkPolyData = Utilities.getPolyDataActor(polyData)
    centerPointActor: vtkActor = Utilities.getPointsActorList([
        ptCenter, xLeftPoint, xRightPoint, yBottomPoint, yTopPoint, zFrontPoint, zBacktPoint])


    Utilities.DisplayActors([centerPointActor, teethActor])


if __name__ == '__main__':
    Test()