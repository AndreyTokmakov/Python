from typing import Dict, List

# noinspection PyUnresolvedReferences
import vtk
import vtkmodules.vtkInteractionStyle
# noinspection PyUnresolvedReferences
import vtkmodules.vtkRenderingOpenGL2
from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersSources import vtkSphereSource
from vtkmodules.vtkRenderingAnnotation import vtkAxesActor
from vtkmodules.vtkRenderingCore import (
    vtkActor,
    vtkPolyDataMapper,
    vtkRenderWindow,
    vtkRenderWindowInteractor,
    vtkRenderer
)

from VTK_Experiments.Utilities import Utilities


class PointsTests(object):

    @staticmethod
    def Test():
        pts = [(1, 2, 0), (2, 3, 0), (3, 4, 0)]
        actor: vtkActor = Utilities.getPointsActor(pts)
        Utilities.DisplayActors([actor])

    @staticmethod
    def DrawParabola():
        a1, b1, c1 = 0.2, 0.0, 0.0
        pts1: List = []
        for x in range(-10, 11):
            y = a1 * x * x + b1 * x + c1
            pts1.append((x, y, 0))
            print(x, y)

        actor1: vtkActor = Utilities.getPointsActor(pts1)

        a2, b2, c2 = 0.2, 0.0, 1.0
        pts2: List = []
        for x in range(-10, 11):
            y = a2 * x * x + b2 * x + c2
            pts2.append((x, y, 0))
            print(x, y)

        actor2: vtkActor = Utilities.getPointsActor(pts2, color=[1, 0, 1])

        Utilities.DisplayActors([actor1, actor2])


if __name__ == '__main__':
    # PointsTests.Test()
    PointsTests.DrawParabola()
