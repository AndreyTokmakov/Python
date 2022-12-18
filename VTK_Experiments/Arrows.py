from typing import List

from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkFiltersSources import vtkArrowSource, vtkConeSource, vtkLineSource
from vtkmodules.vtkRenderingCore import vtkActor, vtkPolyDataMapper
from VTK_Experiments.Utilities import Utilities

import numpy as np
import vtk



def Test1():
    arrow1 = vtkArrowSource()
    arrow1.SetTipResolution(8)
    arrow1.SetTipLength(0.2)
    arrow1.SetTipRadius(0.05)
    arrow1.SetInvert(True)
    arrow1.Update()

    arrow2 = vtkArrowSource()
    arrow2.SetTipResolution(8)
    arrow2.SetTipLength(0.3)
    arrow2.SetTipRadius(0.05)
    arrow2.Update()

    pd = Utilities.getPolyDataListActor([arrow1.GetOutput(), arrow2.GetOutput()])

    Utilities.DisplayActors([pd])

'''
def GetArrowLine(pt1: List,
                 pt2: List,
                 color: List = [0, 1, 0]) -> vtkPolyData:
    pt1 = np.asarray(pt1)
    pt2 = np.asarray(pt2)

    cone1 = vtkConeSource()
    cone1.SetHeight(1.0)
    cone1.SetRadius(0.05)
    cone1.SetAngle(9)
    cone1.SetResolution(9)
    cone1.SetCenter(pt2)
    cone1.SetDirection(pt1)
    cone1.Update()

    bounds1 = cone1.GetOutput().GetBounds()
    cone1.SetCenter(pt2 - np.array([(bounds1[1] - bounds1[0]) / 2, 0, 0]))
    cone1.Update()

    cone2 = vtkConeSource()
    cone2.SetHeight(1.0)
    cone2.SetRadius(0.05)
    cone2.SetAngle(9)
    cone2.SetResolution(9)
    cone2.SetCenter(pt1)
    cone2.SetDirection(pt2 * -1)
    cone2.Update()

    bounds2 = cone2.GetOutput().GetBounds()
    cone2.SetCenter(pt1 + np.array([(bounds2[1] - bounds2[0]) / 2, 0, 0]))
    cone2.Update()

    vtkLine: vtkLineSource = vtkLineSource()
    vtkLine.SetPoint1(pt1)
    vtkLine.SetPoint2(pt2)
    vtkLine.Update()

    return Utilities.appendPolyData([vtkLine.GetOutput(), cone1.GetOutput(), cone2.GetOutput()])
'''

def GetArrowLine_Actors(pt1: List,
                        pt2: List,
                        color: List = [0, 1, 0]) -> vtkPolyData:
    pt1 = np.asarray(pt1)
    pt2 = np.asarray(pt2)

    cone1 = vtkConeSource()
    cone1.SetHeight(1.0)
    cone1.SetRadius(0.05)
    cone1.SetAngle(9)
    cone1.SetResolution(9)
    cone1.SetCenter(pt2)
    cone1.SetDirection(pt2 - pt1)
    cone1.Update()

    bounds1 = cone1.GetOutput().GetBounds()
    cone1.SetCenter(pt2 - np.array([(bounds1[1] - bounds1[0]) / 2, 0, 0]))
    cone1.Update()

    cone2 = vtkConeSource()
    cone2.SetHeight(1.0)
    cone2.SetRadius(0.05)
    cone2.SetAngle(9)
    cone2.SetResolution(9)
    cone2.SetCenter(pt1)
    cone2.SetDirection(pt1 - pt2)
    cone2.Update()

    bounds2 = cone2.GetOutput().GetBounds()
    cone2.SetCenter(pt1 + np.array([(bounds2[1] - bounds2[0]) / 2, 0, 0]))
    cone2.Update()

    lineActor: vtkActor = Utilities.getLineActorFromPoints(pt1, pt2)
    coneActor: vtkActor = Utilities.getPolyDataListActor([cone1.GetOutput(), cone2.GetOutput()])
    coneActor.GetProperty().SetColor(0, 1, 0)

    return [lineActor, coneActor]


def Create_ArrowLikeLine2():
    pt1 = np.asarray([1, 31, 0])
    pt2 = np.asarray([6, 31, 0])

    actors = GetArrowLine_Actors(pt1, pt2)
    Utilities.DisplayActors(actors)


def Create_ArrowLikeLine():
    pt1 = np.asarray([1, 0, 0])
    pt2 = np.asarray([6, 0, 0])

    cone1 = vtkConeSource()
    cone1.SetHeight(1.0)
    cone1.SetRadius(0.05)
    cone1.SetAngle(9)
    cone1.SetResolution(9)
    cone1.SetCenter(pt2)
    cone1.SetDirection(pt1)
    cone1.Update()

    bounds1 = cone1.GetOutput().GetBounds()
    cone1.SetCenter(pt2 - np.array([(bounds1[1] - bounds1[0]) / 2, 0, 0]))
    cone1.Update()

    cone2 = vtkConeSource()
    cone2.SetHeight(1.0)
    cone2.SetRadius(0.05)
    cone2.SetAngle(9)
    cone2.SetResolution(9)
    cone2.SetCenter(pt1)
    cone2.SetDirection(pt2 * -1)
    cone2.Update()

    bounds2 = cone2.GetOutput().GetBounds()
    cone2.SetCenter(pt1 + np.array([(bounds2[1] - bounds2[0]) / 2, 0, 0]))
    cone2.Update()

    lineActor: vtkActor = Utilities.getLineActorFromPoints(pt1, pt2)
    coneActor: vtkActor = Utilities.getPolyDataListActor([cone1.GetOutput(), cone2.GetOutput()])
    coneActor.GetProperty().SetColor(0, 1, 0)
    Utilities.DisplayActors([coneActor, lineActor])


if __name__ == '__main__':
    # Create_ArrowLikeLine()
    Create_ArrowLikeLine2()
