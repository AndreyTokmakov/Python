from typing import Dict, List, Tuple

import numpy as np
import vtkmodules.vtkInteractionStyle
import vtkmodules.vtkRenderingOpenGL2
from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkCommonCore import vtkPoints
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersCore import vtkAppendPolyData, vtkCleanPolyData
from vtkmodules.vtkFiltersGeneral import vtkVertexGlyphFilter, vtkTransformPolyDataFilter
from vtkmodules.vtkFiltersModeling import vtkOutlineFilter
from vtkmodules.vtkFiltersSources import vtkSphereSource, vtkLineSource
from vtkmodules.vtkRenderingAnnotation import vtkAxesActor
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

from VTK_Experiments.Types import Point2D, Point3D, Line3D


class Utilities(object):
    __colors: vtkNamedColors = vtkNamedColors()

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
            outlineActor.GetProperty().SetColor(Utilities.__colors.GetColor3d("Red"));
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
                         color: Tuple = [0, 0, 0]) -> vtkActor:
        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(polyData)

        actor: vtkActor = vtkActor()
        actor.GetProperty().SetColor(color)
        actor.SetMapper(mapper)
        return actor

    # Combine List[vtkPolyData] to single vtkPolyData object:
    @staticmethod
    def appendPolyData(mesh_seq: List[vtkPolyData], clean=False) -> vtkPolyData:
        append_filter = vtkAppendPolyData()
        for mesh in mesh_seq:
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
    def pointsToPolyData(points: List[Point3D]) -> vtkPolyData:
        vtkPts: vtkPoints = vtkPoints()
        for pt in points:
            vtkPts.InsertNextPoint(pt.as_tuple())

        pointsPolydata: vtkPolyData = vtkPolyData()
        pointsPolydata.SetPoints(vtkPts)

        vertexFilter: vtkVertexGlyphFilter = vtkVertexGlyphFilter()
        vertexFilter.SetInputData(pointsPolydata)
        vertexFilter.Update();

        polydata: vtkPolyData = vtkPolyData()
        polydata.ShallowCopy(vertexFilter.GetOutput())
        return polydata

    @staticmethod
    def getPointsActor(points: List,
                       color: List = [0, 1, 0]) -> vtkActor:
        pts: vtkPoints = vtkPoints()
        for pt in points:
            pts.InsertNextPoint(pt)

        pointsPolydata: vtkPolyData = vtkPolyData()
        pointsPolydata.SetPoints(pts)

        vertexFilter: vtkVertexGlyphFilter = vtkVertexGlyphFilter()
        vertexFilter.SetInputData(pointsPolydata)
        vertexFilter.Update()

        polyData: vtkPolyData = vtkPolyData()
        polyData.ShallowCopy(vertexFilter.GetOutput())

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(polyData)

        actorPoints: vtkActor = vtkActor()
        actorPoints.SetMapper(mapper)
        actorPoints.GetProperty().SetColor(color)
        actorPoints.GetProperty().SetPointSize(12)
        actorPoints.GetProperty().RenderPointsAsSpheresOn()
        return actorPoints

    @staticmethod
    def getLineActor(line: Line3D) -> vtkActor:
        vtkLine: vtkLineSource = vtkLineSource()
        vtkLine.SetPoint1(line.pt1.as_tuple())
        vtkLine.SetPoint2(line.pt2.as_tuple())
        vtkLine.Update()

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(vtkLine.GetOutput())

        actorPoints: vtkActor = vtkActor()
        actorPoints.SetMapper(mapper)
        actorPoints.GetProperty().SetColor(0, 1, 0)
        actorPoints.GetProperty().SetLineWidth(4)
        return actorPoints;

    # TODO: REFACTOR methods
    @staticmethod
    def getLineActorFromPoints(pt1: List,
                               pt2: List,
                               color: List = [0, 1, 0]) -> vtkActor:
        vtkLine: vtkLineSource = vtkLineSource()
        vtkLine.SetPoint1(pt1)
        vtkLine.SetPoint2(pt2)
        vtkLine.Update()

        mapper: vtkPolyDataMapper = vtkPolyDataMapper()
        mapper.SetInputData(vtkLine.GetOutput())

        actorPoints: vtkActor = vtkActor()
        actorPoints.SetMapper(mapper)
        actorPoints.GetProperty().SetColor(color)
        actorPoints.GetProperty().SetLineWidth(3)
        return actorPoints;

    @staticmethod
    def DisplayActors(actors: List[vtkActor],
                      windowName: str = "VTK Window") -> None:
        renderer: vtkRenderer = vtkRenderer()
        renderer.SetBackground(Utilities.__colors.GetColor3d('DimGray'))
        for actor in actors:
            renderer.AddActor(actor)

        renderWindow: vtkRenderWindow = vtkRenderWindow()
        renderWindow.SetWindowName(windowName)
        renderWindow.SetSize(1200, 800)
        renderWindow.SetPosition(200, 50)
        renderWindow.AddRenderer(renderer)

        wndowInteractor: vtkRenderWindowInteractor = vtkRenderWindowInteractor()
        wndowInteractor.SetRenderWindow(renderWindow)

        renderWindow.Render()
        wndowInteractor.Start()

'''
    vtkSmartPointer<vtkActor> getLineActor(const Types::Line<3>& line,
                                           const vtkSmartPointer<vtkNamedColors>& colors)
    {
        vtkSmartPointer<vtkLineSource> lineSource {vtkLineSource::New()};
        vtkSmartPointer<vtkPolyDataMapper> mapper { vtkPolyDataMapper::New() };
        vtkSmartPointer<vtkActor> actor { vtkActor::New() };
        lineSource->SetPoint1(line.getFirstPoint().data());
        lineSource->SetPoint2(line.getSecondPoint().data()) ;
        lineSource->Update();
        mapper->SetInputData( lineSource->GetOutput() );
        actor->SetMapper(mapper);
        actor->GetProperty()->SetColor( 0, 1, 0 );
        actor->GetProperty()->SetLineWidth(4);
        return actor;
    }

'''