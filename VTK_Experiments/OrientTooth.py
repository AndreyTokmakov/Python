from typing import Set
import  numpy
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkPlane
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersCore import vtkCutter, vtkClipPolyData
from vtkmodules.vtkFiltersGeneral import vtkOBBTree, vtkTransformPolyDataFilter
from vtkmodules.vtkFiltersSources import vtkLineSource
from vtkmodules.vtkRenderingCore import vtkActor, vtkPolyDataMapper

from VTK_Experiments.Utilities import Utilities


class ToothOrientation(object):

    upperTeeth: Set = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}

    def rotatePolyData(self,
                       polyData: vtkPolyData,
                       xAngle: float,
                       yAngle: float,
                       zAngle: float) -> vtkPolyData:
        transform: vtkTransform = vtkTransform()
        transform.RotateX(xAngle)
        transform.RotateY(yAngle)
        transform.RotateZ(zAngle)

        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
        transformFilter.Update()

        return transformFilter.GetOutput()


    def getAngulationAngle(self,
                           polyData: vtkPolyData,
                           tooth_id: int) -> int:
        angle, xMin = 0, 1000  # TODO: Fix '1000' hardcode
        for angleToRotate in range(-45, 45):
            data = self.rotatePolyData(polyData, 0, 0, angleToRotate)
            bounds = data.GetBounds()
            xDist = bounds[1] - bounds[0]
            if xMin > xDist:
                xMin, angle = xDist, angleToRotate

        return angle


    def getAngulationAngleY(self,
                           polyData: vtkPolyData,
                           tooth_id: int) -> int:
        angle, xMin = 0, 1000  # TODO: Fix '1000' hardcode
        for angleToRotate in range(-15, 15):
            data = self.rotatePolyData(polyData, 0, 0, angleToRotate)
            bounds = data.GetBounds()
            xDist = bounds[3] - bounds[2]
            if xMin > xDist:
                xMin, angle = xDist, angleToRotate

        return angle

    def getRotationAngle(self,
                         polyData: vtkPolyData,
                         tooth_id: int) -> int:
        center = list(polyData.GetCenter())  # TODO: --> to numpy ???
        bounds = polyData.GetBounds()
        start = bounds[2] - center[1]
        end = bounds[3] - center[1]

        clip: vtkClipPolyData = vtkClipPolyData()
        clip.SetInputData(polyData)

        if tooth_id in self.upperTeeth:
            clip.InsideOutOn()
            center[1] += start + 3  # Upper tooth part (Upper - 1)
        else:
            center[1] += end - 1  # Lower tooth part (Bottom + 3)

        plane: vtkPlane = vtkPlane()
        plane.SetOrigin(center)
        plane.SetNormal(0, 1, 0)

        clip.SetClipFunction(plane)
        clip.Update()
        polyData: vtkPolyData = clip.GetOutput()

        angle, maxDist = 0, 0
        for angleToRotate in range(-45, 45):
            data = self.rotatePolyData(polyData, 0, angleToRotate, 0)
            #Utilities.visualize(data, True)
            bounds = data.GetBounds()
            xDistance = bounds[1] - bounds[0]
            if xDistance > maxDist:
                maxDist, angle = xDistance, angleToRotate

        return angle


    def OrientTooth(self,
                    polyData: vtkPolyData,
                    tooth_id: int) -> vtkPolyData:
        angulation: int = self.getAngulationAngle(polyData, tooth_id)
        polyData = self.rotatePolyDataY(polyData, 0, 0, angulation)

        rotation: int = self.getRotationAngle(polyData, tooth_id)
        polyData = self.rotatePolyData(polyData, 0, rotation, 0)
        return polyData


class ToothOrientation2(object):

    upperTeeth: Set = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}

    def getLineActor(self, line) -> vtkActor:
        vtkLine: vtkLineSource = vtkLineSource()
        vtkLine.SetPoint1(line[0])
        vtkLine.SetPoint2(line[1])
        vtkLine.Update()

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(vtkLine.GetOutput())

        actor: vtkActor = vtkActor()
        actor.SetMapper(mapper)
        actor.GetProperty().SetColor(0, 1, 0)
        actor.GetProperty().SetLineWidth(4)
        return actor;

    def _displayOBB(self, data: vtkPolyData):
        obbTree = vtkOBBTree()
        obbTree.SetDataSet(data)
        obbTree.SetMaxLevel(1)
        obbTree.BuildLocator()

        pd: vtkPolyData = vtkPolyData()
        obbTree.GenerateRepresentation(0, pd);

        actor = Utilities.getPolyDataActor(pd)
        actor.GetProperty().SetOpacity(.3);

        toothActor = Utilities.getPolyDataActor(data)
        Utilities.DisplayActors([toothActor, actor])

    def rotatePolyData(self,
                       polyData: vtkPolyData,
                       xAngle: float,
                       yAngle: float,
                       zAngle: float) -> vtkPolyData:
        transform: vtkTransform = vtkTransform()
        transform.RotateX(xAngle)
        transform.RotateY(yAngle)
        transform.RotateZ(zAngle)

        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
        transformFilter.Update()

        return transformFilter.GetOutput()

    def getRotationAngle(self,
                         polyData: vtkPolyData,
                         tooth_id: int) -> int:
        center = list(polyData.GetCenter())  # TODO: --> to numpy ???
        bounds = polyData.GetBounds()
        start, end = bounds[2] - center[1], bounds[3] - center[1]

        clip: vtkClipPolyData = vtkClipPolyData()
        clip.SetInputData(polyData)

        if tooth_id in self.upperTeeth:
            clip.InsideOutOn()
            center[1] += start + 1  # Upper tooth part (Upper - 1)
        else:
            center[1] += end - 1  # Lower tooth part (Bottom + 3)

        plane: vtkPlane = vtkPlane()
        plane.SetOrigin(center)
        plane.SetNormal(0, 1, 0)

        clip.SetClipFunction(plane)
        clip.Update()
        polyData: vtkPolyData = clip.GetOutput()


        res_corner = numpy.array([0.]*3)
        res_max = numpy.array([0.]*3)
        res_mid = numpy.array([0.]*3)
        res_min = numpy.array([0.]*3)
        res_size = numpy.array([0.]*3)
        obb_tree = vtkOBBTree()
        obb_tree.ComputeOBB(polyData, res_corner, res_max, res_mid, res_min, res_size)

        print(center)
        print(bounds)

        print('----------------------------------------------------------------------')

        print(res_corner)
        print(res_max)
        print(res_mid)
        print(res_min)


        actor = self.getLineActor([[1,1,1], [5,5,5]])
        Utilities.DisplayActors([actor])

        # Utilities.visualize(polyData, True)
        # self._displayOBB(polyData)

        return 0



#######################################################################################

def TestOrientation():
    # STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'
    # STL_FILE = '/home/andtokm/Projects/data/out/Tooths/tooth_8.stl'
    # STL_FILE = '/home/andtokm/Projects/data/out/Tooths/31_tooth.stl'
    tooth_Stl_22 = '/home/andtokm/Projects/data/out/Tooths/22_tooth.stl'
    #tooth_Stl_13 = '/home/andtokm/Projects/data/out/Tooths/13_tooth.stl'

    tooth_id: int = 22
    orient = ToothOrientation()
    polyData: vtkPolyData = Utilities.readStl(tooth_Stl_22)

    Utilities.visualize(polyData, True)

    # polyData = orient.OrientTooth(polyData)
    # Utilities.visualize(polyData, True)

    angulation: int = orient.getAngulationAngle(polyData, tooth_id)
    polyData = orient.rotatePolyData(polyData, 0, 0, angulation)

    rotation: int = orient.getRotationAngle(polyData, tooth_id)

    polyData = orient.rotatePolyData(polyData, 0, rotation, 0)
    Utilities.visualize(polyData, True)


def TestOrientation2():
    # STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'
    # STL_FILE = '/home/andtokm/Projects/data/out/Tooths/tooth_8.stl'
    # STL_FILE = '/home/andtokm/Projects/data/out/Tooths/31_tooth.stl'
    tooth_Stl_22 = '/home/andtokm/Projects/data/out/Tooths/22_tooth.stl'
    #tooth_Stl_13 = '/home/andtokm/Projects/data/out/Tooths/13_tooth.stl'

    tooth_id: int = 22
    orient = ToothOrientation2()
    polyData: vtkPolyData = Utilities.readStl(tooth_Stl_22)

    # Utilities.visualize(polyData, True)

    # polyData = orient.OrientTooth(polyData)
    # Utilities.visualize(polyData, True)

    # angulation: int = orient.getAngulationAngle(polyData, tooth_id)
    # polyData = orient.rotatePolyData(polyData, 0, 0, angulation)

    rotation: int = orient.getRotationAngle(polyData, tooth_id)

    # polyData = orient.rotatePolyData(polyData, 0, rotation, 0)
    # Utilities.visualize(polyData, True)


def TestTransfom():
    # STL_FILE = '/home/andtokm/Projects/data/out/Tooths/tooth_7.stl'
    STL_FILE = '/home/andtokm/Projects/data/out/Tooths/31_tooth.stl'
    polyData: vtkPolyData = Utilities.readStl(STL_FILE)
    orient = ToothOrientation()

    polyData = orient.rotatePolyData(polyData, 0, 31, 4)
    Utilities.visualize(polyData, True)


if __name__ == '__main__':
    # TestOrientation();
    TestOrientation2();
    # TestTransfom()
