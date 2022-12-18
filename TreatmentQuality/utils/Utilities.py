from typing import Dict, List, Tuple

import math
import numpy as np
from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkCommonCore import vtkPoints, reference
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkLine
from vtkmodules.vtkCommonMath import vtkMatrix4x4
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersCore import vtkAppendPolyData, vtkCleanPolyData
from vtkmodules.vtkFiltersGeneral import vtkVertexGlyphFilter, vtkTransformPolyDataFilter
from vtkmodules.vtkFiltersModeling import vtkOutlineFilter
from vtkmodules.vtkFiltersSources import vtkLineSource
from vtkmodules.vtkIOGeometry import (
    vtkSTLReader, vtkOBJReader, vtkSTLWriter
)
from vtkmodules.vtkRenderingCore import (
    vtkActor,
    vtkPolyDataMapper,
    vtkRenderWindow,
    vtkRenderWindowInteractor,
    vtkRenderer
)


class Utilities(object):
    UPPER_TEETH = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28]
    LOWER_TEETH = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38]

    __colors: vtkNamedColors = vtkNamedColors()

    @staticmethod
    def moveTooth(polyData: vtkPolyData,
                  x: float,
                  y: float,
                  z: float) -> vtkPolyData:
        transformation: vtkTransform = vtkTransform()
        transformation.Translate(x, y, z)

        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transformation)
        transformFilter.Update()

        return transformFilter.GetOutput()

    # TODO: Move data on {xDist, yDist, zDist}
    @staticmethod
    def setPolyDataCenter(polyData: vtkPolyData,
                          x: float,
                          y: float,
                          z: float) -> vtkPolyData:
        ptCenter: Tuple = polyData.GetCenter()
        xDist, yDist, zDist = x - ptCenter[0], y - ptCenter[1], z - ptCenter[2]
        return Utilities.moveTooth(polyData, xDist, yDist, zDist)

    # FIXME: Build it manually - do not use VTK
    # TODO: Research for existing solutions
    @staticmethod
    def buildRotation_matrix_bad(xAngle: float,
                                 yAngle: float,
                                 zAngle: float) -> vtkMatrix4x4:
        transform: vtkTransform = vtkTransform()
        transform.RotateX(xAngle)
        transform.RotateY(yAngle)
        transform.RotateZ(zAngle)

        matrix: vtkMatrix4x4 = vtkMatrix4x4()
        transform.GetMatrix(matrix)
        return matrix

    # TODO: Check is there is some more better way to do it
    @staticmethod
    def vtkMatrixToNumpy(mat: vtkMatrix4x4) -> np.ndarray:
        temp = [0] * 16
        mat.DeepCopy(temp, mat)
        mat = np.array(temp).reshape(4, 4)
        mat = np.delete(np.asarray(mat), np.s_[3], axis=0)
        return np.delete(mat, np.s_[3], axis=1)

    @staticmethod
    def angle_between_vectors(vector1: np.ndarray,
                              vector2: np.ndarray) -> float:
        a = np.dot(vector1, vector2)
        b = np.sqrt(np.dot(vector1, vector1)) * np.sqrt(np.dot(vector2, vector2))
        return math.acos(a / b) * 180 / math.pi

    # Calculate the line Slope-Intercept equation coefficients
    # 2D only
    @staticmethod
    def get_line_coefficients(pt1: List, pt2: List):
        # angular coefficient - tilt to the XS-axis
        slope = (pt2[1] - pt1[1]) / (pt2[0] - pt1[0])
        # straight line offset - the segment cut off from the axis
        intercept = (pt2[0] * pt1[1] - pt1[0] * pt2[1]) / (pt2[0] - pt1[0])

        return slope, intercept

    # Calculate distance between two 3D points
    @staticmethod
    def distance_between_two_points(pt1: List[float],
                                    pt2: List[float]) -> float:
        pt1: np.ndarray = np.asarray(pt1)
        pt2: np.ndarray = np.asarray(pt2)
        return math.sqrt(np.square(pt1 - pt2).sum())

    # Calculate distance between two 3D points
    # Returns Tuple[float, List] where 'float' - distance and 'List' is closest point
    @staticmethod
    def distance_to_line(pt_from: List[float],
                         pt_line1: List[float],
                         pt_line2: List[float]) -> Tuple[float, List]:
        t: reference = reference(1.0)
        closest: List[float, float, float] = [0.0, 0.0, 0.0]
        dist: float = vtkLine().DistanceToLine(pt_from, pt_line1, pt_line2, t, closest)

        return math.sqrt(dist), closest

    # Simple vtk.vtkPolyData visualization
    @staticmethod
    def visualize(polyData: vtkPolyData,
                  showBBox: bool = False,
                  windowName: str = "VTK Window"):
        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(polyData)

        actor: vtkActor = vtkActor()
        actor.SetMapper(mapper)

        renderer: vtkRenderer = vtkRenderer()
        renderer.AddActor(actor)
        renderer.SetBackground(Utilities.__colors.GetColor3d('DimGray'))

        if showBBox:
            outlineFilter: vtkOutlineFilter = vtkOutlineFilter()
            outlineFilter.SetInputData(polyData)

            outlineMapper: vtkPolyDataMapper = vtkPolyDataMapper()
            outlineMapper.SetInputConnection(outlineFilter.GetOutputPort())

            outlineActor: vtkActor = vtkActor()
            outlineActor.SetMapper(outlineMapper)
            outlineActor.GetProperty().SetColor(Utilities.__colors.GetColor3d("Red"))
            renderer.AddActor(outlineActor)

        renderWindow: vtkRenderWindow = vtkRenderWindow()
        renderWindow.SetWindowName(windowName)
        renderWindow.SetSize(1200, 800)
        renderWindow.SetPosition(200, 50)
        renderWindow.AddRenderer(renderer)

        renderWindow.Render()
        windowInteractor: vtkRenderWindowInteractor = vtkRenderWindowInteractor()
        windowInteractor.SetRenderWindow(renderWindow)
        windowInteractor.Start()

    # Write .STL file data:
    @staticmethod
    def writeStl(polyData: vtkPolyData,
                 filePath: str) -> None:
        writer = vtkSTLWriter()
        writer.SetFileTypeToBinary
        writer.SetFileName(filePath)
        writer.SetInputData(polyData)
        writer.Write()

    # Read .STL file data:
    @staticmethod
    def readStl(filePath: str) -> vtkPolyData:
        reader = vtkSTLReader()
        reader.SetFileName(filePath)
        reader.Update()
        return reader.GetOutput()

    # Read .OBJ file data:
    @staticmethod
    def readObj(filePath: str) -> vtkPolyData:
        reader = vtkOBJReader()
        reader.SetFileName(filePath)
        reader.Update()
        return reader.GetOutput()

    # Create vtkMapper for given vtkPolyData data object:
    @staticmethod
    def getPolyDataActor(polyData: vtkPolyData,
                         color: List = [1, 1, 1]) -> vtkActor:
        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(polyData)

        actor: vtkActor = vtkActor()
        actor.SetMapper(mapper)
        actor.GetProperty().SetColor(color)
        return actor

    # Combine List[vtkPolyData] to single vtkPolyData object:
    @staticmethod
    def appendPolyData(pdList: List[vtkPolyData], clean=False) -> vtkPolyData:
        append_filter = vtkAppendPolyData()
        for mesh in pdList:
            append_filter.AddInputData(mesh)
        append_filter.Update()
        result = append_filter.GetOutput()
        if clean:
            clean_filter = vtkCleanPolyData()
            clean_filter.SetInputData(result)
            clean_filter.Update()
            result = clean_filter.GetOutput()
        return result

    # Rotate the polyData object
    @staticmethod
    def rotatePolyData(polyData: vtkPolyData,
                       xAngle: float = 0,
                       yAngle: float = 0,
                       zAngle: float = 0) -> vtkPolyData:
        transform: vtkTransform = vtkTransform()
        transform.RotateX(xAngle)
        transform.RotateY(yAngle)
        transform.RotateZ(zAngle)

        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
        transformFilter.Update()
        return transformFilter.GetOutput()

    # Create vtkOutlineFilter actor
    @staticmethod
    def getOutlineActor(polyData: vtkPolyData) -> vtkActor:
        outlineFilter: vtkOutlineFilter = vtkOutlineFilter()
        outlineFilter.SetInputData(polyData)

        outlineMapper: vtkPolyDataMapper = vtkPolyDataMapper()
        outlineMapper.SetInputConnection(outlineFilter.GetOutputPort())

        actor: vtkActor = vtkActor()
        actor.SetMapper(outlineMapper)
        actor.GetProperty().SetColor(1.0, 0.0, 0.0)

        return actor

    # Create vtkMapper for a List of vtkPolyData data objects:
    @staticmethod
    def getPolyDataListActor(polyDataList: List[vtkPolyData]) -> vtkActor:
        dataAppender: vtkAppendPolyData = vtkAppendPolyData()
        for data in polyDataList:
            dataAppender.AddInputData(data)
        dataAppender.Update()

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(dataAppender.GetOutput())

        actor: vtkActor = vtkActor()
        actor.SetMapper(mapper)
        return actor

    @staticmethod
    def pointsToPolyData(points: List) -> vtkPolyData:
        vtkPts: vtkPoints = vtkPoints()
        for pt in points:
            vtkPts.InsertNextPoint(pt)

        pointsPolyData: vtkPolyData = vtkPolyData()
        pointsPolyData.SetPoints(vtkPts)

        vertexFilter: vtkVertexGlyphFilter = vtkVertexGlyphFilter()
        vertexFilter.SetInputData(pointsPolyData)
        vertexFilter.Update()

        polyData: vtkPolyData = vtkPolyData()
        polyData.ShallowCopy(vertexFilter.GetOutput())
        return polyData

    @staticmethod
    def getPointsActor(points: List,
                       color: List = [1, 0, 0],
                       size: float = 12.0) -> vtkActor:
        pts: vtkPoints = vtkPoints()
        for pt in points:
            pts.InsertNextPoint(pt)

        pointsPolyData: vtkPolyData = vtkPolyData()
        pointsPolyData.SetPoints(pts)

        vertexFilter: vtkVertexGlyphFilter = vtkVertexGlyphFilter()
        vertexFilter.SetInputData(pointsPolyData)
        vertexFilter.Update()

        polyData: vtkPolyData = vtkPolyData()
        polyData.ShallowCopy(vertexFilter.GetOutput())

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(polyData)

        actorPoints: vtkActor = vtkActor()
        actorPoints.SetMapper(mapper)
        actorPoints.GetProperty().SetColor(color)
        actorPoints.GetProperty().SetPointSize(size)
        actorPoints.GetProperty().RenderPointsAsSpheresOn()
        return actorPoints

    # TODO: REFACTOR methods
    @staticmethod
    def getLineActor(pt1: List,
                     pt2: List,
                     color: List = [0, 1, 0],
                     width: float = 3.0) -> vtkActor:
        vtkLine: vtkLineSource = vtkLineSource()
        vtkLine.SetPoint1(pt1)
        vtkLine.SetPoint2(pt2)
        vtkLine.Update()

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(vtkLine.GetOutput())

        actorPoints: vtkActor = vtkActor()
        actorPoints.SetMapper(mapper)
        actorPoints.GetProperty().SetColor(color)
        actorPoints.GetProperty().SetLineWidth(width)
        return actorPoints

    # TODO: REFACTOR methods
    @staticmethod
    def getLinePolyData(pt1: List,
                        pt2: List) -> vtkActor:
        vtkLine: vtkLineSource = vtkLineSource()
        vtkLine.SetPoint1(pt1)
        vtkLine.SetPoint2(pt2)
        vtkLine.Update()

        return vtkLine.GetOutput()

    @staticmethod
    def DisplayActors(actors: List[vtkActor],
                      windowName: str = "VTK Window",
                      position: Tuple = (200, 50),
                      size: Tuple = (1200, 800)) -> None:
        renderer: vtkRenderer = vtkRenderer()
        renderer.SetBackground(Utilities.__colors.GetColor3d('DimGray'))
        for actor in actors:
            renderer.AddActor(actor)

        renderWindow: vtkRenderWindow = vtkRenderWindow()
        renderWindow.SetWindowName(windowName)
        renderWindow.SetSize(size)
        renderWindow.SetPosition(position)
        renderWindow.AddRenderer(renderer)

        wndowInteractor: vtkRenderWindowInteractor = vtkRenderWindowInteractor()
        wndowInteractor.SetRenderWindow(renderWindow)

        renderWindow.Render()
        wndowInteractor.Start()
