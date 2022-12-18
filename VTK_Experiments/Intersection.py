import numpy as np

from typing import Dict

from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersGeneral import vtkIntersectionPolyDataFilter, vtkTransformPolyDataFilter, \
    vtkBooleanOperationPolyDataFilter
from vtkmodules.vtkRenderingCore import vtkActor

from VTK_Experiments.Utilities import Utilities
from VTK_Experiments.utils.ToothOBJWorker import ToothOBJWorker


def moveTooth(polyData: vtkPolyData,
              x: float, y: float, z: float) -> vtkPolyData:
    transformation: vtkTransform = vtkTransform()
    transformation.Translate(x, y, z)

    transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
    transformFilter.SetInputData(polyData)
    transformFilter.SetTransform(transformation)
    transformFilter.Update()

    return transformFilter.GetOutput()


def rotateData(polyData: vtkPolyData,
               x: float, y: float, z: float) -> vtkPolyData:
    transformation: vtkTransform = vtkTransform()
    transformation.RotateX(x)
    transformation.RotateY(y)
    transformation.RotateZ(z)

    transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
    transformFilter.SetInputData(polyData)
    transformFilter.SetTransform(transformation)
    transformFilter.Update()

    return transformFilter.GetOutput()


def vtkBooleanPolyDataFilter():
    pass


def IntersectionTest():
    CASE_ID = '2630'
    file_path = f'S:\Projects\TEST_DATA\{CASE_ID}\models\dd17_scan_crown.obj'

    worker = ToothOBJWorker(file_path)
    teethMap: Dict[int, vtkPolyData] = worker.teethMap

    tooth1: vtkPolyData = teethMap[11]
    tooth2: vtkPolyData = teethMap[21]

    tooth1 = moveTooth(tooth1, 1, 0, 0)

    booleanFilter = vtkBooleanOperationPolyDataFilter()
    booleanFilter.SetOperationToUnion()
    booleanFilter.SetInputData(0, tooth1)
    booleanFilter.SetInputData(1, tooth2)
    booleanFilter.GlobalWarningDisplayOff()
    booleanFilter.Update()

    # print(booleanFilter.)

    # center: np.ndarray = np.asarray(intersectionFilter.GetOutput().GetCenter())
    # centerActor: vtkActor = Utilities.getPointsActor([center], color=[1, 0, 0])

    actor: vtkActor = Utilities.getPolyDataListActor([tooth1, tooth2])
    Utilities.DisplayActors([actor])


def IntersectionTest_IntersectionPolyDataFilter():
    CASE_ID = '2630'
    file_path = f'S:\Projects\TEST_DATA\{CASE_ID}\models\dd17_scan_crown.obj'

    worker = ToothOBJWorker(file_path)
    teethMap: Dict[int, vtkPolyData] = worker.teethMap

    tooth11: vtkPolyData = teethMap[11]
    tooth21: vtkPolyData = teethMap[21]

    tooth11 = moveTooth(tooth11, 1, 0, 0)

    intersectionFilter = vtkIntersectionPolyDataFilter()
    intersectionFilter.SetInputData(0, tooth11)
    intersectionFilter.SetInputData(1, tooth21)
    intersectionFilter.ComputeIntersectionPointArrayOff()
    intersectionFilter.CheckMeshOff()
    intersectionFilter.GlobalWarningDisplayOff()
    intersectionFilter.ReleaseDataFlagOff()
    intersectionFilter.DebugOff()
    intersectionFilter.SplitFirstOutputOff()
    intersectionFilter.SplitSecondOutputOff()
    intersectionFilter.CheckInputOff()

    intersectionFilter.Update()

    # center: np.ndarray = np.asarray(intersectionFilter.GetOutput().GetCenter())
    # centerActor: vtkActor = Utilities.getPointsActor([center], color=[1, 0, 0])

    actor: vtkActor = Utilities.getPolyDataListActor([tooth11, tooth21])
    Utilities.DisplayActors([actor])


def IntersectionTest_WithMove():
    CASE_ID = '2630'
    file_path = f'S:\Projects\TEST_DATA\{CASE_ID}\models\dd17_scan_crown.obj'

    worker = ToothOBJWorker(file_path)
    teethMap: Dict[int, vtkPolyData] = worker.teethMap

    tooth11: vtkPolyData = teethMap[11]
    tooth21: vtkPolyData = teethMap[21]

    tooth11 = moveTooth(tooth11, 1, 0, 0)
    pos = 0.0
    while pos < 2.0:
        tooth11 = moveTooth(tooth11, -pos, 0, 0)
        pos += 0.1

        intersectionFilter = vtkIntersectionPolyDataFilter()
        intersectionFilter.SetInputData(0, tooth11)
        intersectionFilter.SetInputData(1, tooth21)
        intersectionFilter.GlobalWarningDisplayOff()
        intersectionFilter.Update()

        if intersectionFilter.GetNumberOfIntersectionPoints() > 0:
            break

        Utilities.DisplayActors([Utilities.getPolyDataListActor([tooth11, tooth21])])

    intersectionFilter = vtkIntersectionPolyDataFilter()
    intersectionFilter.SetInputData(0, tooth11)
    intersectionFilter.SetInputData(1, tooth21)
    intersectionFilter.ComputeIntersectionPointArrayOff()
    intersectionFilter.Update()

    center: np.ndarray = np.asarray(intersectionFilter.GetOutput().GetCenter())

    actor: vtkActor = Utilities.getPolyDataListActor([tooth11, tooth21])
    actor2: vtkActor = Utilities.getPointsActor([center], color=[1, 0, 0])
    Utilities.DisplayActors([actor, actor2])


if __name__ == '__main__':
    # IntersectionTest()
    # IntersectionTest_IntersectionPolyDataFilter()
    IntersectionTest_WithMove()
