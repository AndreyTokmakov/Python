from pathlib import Path

import math
import os
import json
import sys
from typing import Dict, List, Tuple, Set

import vtk as vtk
import numpy as np

import vtkmodules.vtkInteractionStyle
import vtkmodules.vtkRenderingOpenGL2
from _io import TextIOWrapper
from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkCommonCore import vtkPoints
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkPlane
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersCore import vtkCutter, vtkClipPolyData
from vtkmodules.vtkFiltersGeneral import vtkTransformPolyDataFilter, vtkVertexGlyphFilter, vtkOBBTree
from vtkmodules.vtkFiltersModeling import vtkOutlineFilter
from vtkmodules.vtkFiltersSources import vtkSphereSource, vtkLineSource, vtkConeSource
from vtkmodules.vtkRenderingAnnotation import vtkAxesActor
from vtkmodules.vtkRenderingCore import (
    vtkActor,
    vtkPolyDataMapper,
    vtkRenderWindow,
    vtkRenderWindowInteractor,
    vtkRenderer, vtkTextActor
)

from Features import ExtractFeatures
from symmetry import GetSymmetryAxis
from utils import save_features
from Automodeling.Types import Point3D, Line3D
from Automodeling.Utilities import Utilities


#####################################################################################################
#                                      rotatePolyData                                               #
#####################################################################################################

class ToothOrientation(object):
    upperTeeth: Set = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}

    @staticmethod
    def rotatePolyData(polyData: vtkPolyData,
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

    # TODO: Move data on {xDist, yDist, zDist}
    @staticmethod
    def movePolyData(polyData: vtkPolyData,
                     xDist: float,
                     yDist: float,
                     zDist: float) -> vtkPolyData:
        transform: vtkTransform = vtkTransform()
        transform.Translate(xDist, yDist, zDist)

        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
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
        return ToothOrientation.movePolyData(polyData, xDist, yDist, zDist)

    # TODO: Refactor
    def getAngulationAngle(self,
                           polyData: vtkPolyData,
                           tooth_id: int) -> int:
        angle, xMin = 0, 1000  # TODO: Fix '1000' hardcode
        for angleToRotate in range(-45, 45):
            data = ToothOrientation.rotatePolyData(polyData, 0, 0, angleToRotate)
            bounds = data.GetBounds()
            xDist = bounds[1] - bounds[0]
            if xMin > xDist:
                xMin, angle = xDist, angleToRotate

        return angle

    # TODO: Refactor
    def getAngulationAngleY(self,
                            polyData: vtkPolyData,
                            tooth_id: int) -> int:
        angle, xMin = 0, 1000  # TODO: Fix '1000' hardcode
        for angleToRotate in range(-15, 15):
            data = ToothOrientation.rotatePolyData(polyData, 0, 0, angleToRotate)
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
            center[1] += start + 1  # Upper tooth part
        else:
            center[1] += end - 1  # Lower tooth part

        plane: vtkPlane = vtkPlane()
        plane.SetOrigin(center)
        plane.SetNormal(0, 1, 0)

        clip.SetClipFunction(plane)
        clip.Update()
        polyData: vtkPolyData = clip.GetOutput()

        angle, maxDist = 0, 0
        for angleToRotate in range(-45, 45):
            data = ToothOrientation.rotatePolyData(polyData, 0, angleToRotate, 0)
            # Utilities.visualize(data, True)
            bounds = data.GetBounds()
            xDistance = bounds[1] - bounds[0]
            if xDistance > maxDist:
                maxDist, angle = xDistance, angleToRotate

        return angle

    def OrientTooth(self,
                    polyData: vtkPolyData,
                    tooth_id: int) -> vtkPolyData:
        angulation: int = self.getAngulationAngle(polyData, tooth_id)
        polyData = ToothOrientation.rotatePolyData(polyData, 0, 0, angulation)

        rotation: int = self.getRotationAngle(polyData, tooth_id)
        polyData = ToothOrientation.rotatePolyData(polyData, 0, rotation, 0)
        return polyData


#####################################################################################################
#                                    DiagnosticsMethods                                             #
#####################################################################################################

class ToothReader(object):

    def __init__(self,
                 objFileName: str) -> None:
        # TODO: Remove self.jaws
        with open(objFileName, 'rt') as obj_file:
            jaws = self.__read_crowns_model(obj_file)

        self.lowerTeeth: Dict[int, vtkPolyData] = jaws['lower']
        self.upperTeeth: Dict[int, vtkPolyData] = jaws['upper']

        self.teethMap: Dict[int, vtkPolyData] = dict(self.lowerTeeth)
        self.teethMap.update(self.upperTeeth)

    def is_not_empty(self,
                     line: str) -> bool:
        # Return True if we don't skip this line of obj file, False otherwise
        return not (line.strip() == '' or line[0] == '#' or line[:2] in {
            'vt', 'vp'} or line[:6] in {'mtllib', 'usemtl'})

    def __split_lines(self,
                      lines: Tuple[str]) -> Tuple[int, List[str]]:
        """
        Generator for index and splitted lines. Also visualize progress using tqdm.
        :param lines: lines of obj file
        :return: generator of index and splitted line
        """
        for i in range(len(lines)):
            yield i, lines[i].split()
        yield len(lines), []

    def _vector_from_obj_str_split(self,
                                   split: List[str],
                                   v_num: int) -> List[float]:
        if split[0] == 'v':
            return [float(s) for s in split[1:]]
        if split[0] == 'f':
            polygon = []
            for s in split[1:4]:
                s_split = s.split('/')
                if s_split:
                    v_idx = s_split[0]
                else:
                    v_idx = s
                v_idx_int = int(v_idx)
                polygon.append(v_idx_int + v_num if v_idx_int < 0 else v_idx_int - 1)
            return polygon
        if split[0] == 'vn':
            return [float(s) for s in split[1:4]]
        raise ValueError('Syntax error')

    def __read_crowns_model(self,
                            fileObject: TextIOWrapper) -> Dict[str, Dict[int, vtkPolyData]]:
        data_map = {}
        lines = fileObject.readlines()
        lines = tuple(filter(self.is_not_empty, lines))
        if not lines:
            raise ValueError(f'Empty file')
        obj_split = self.__split_lines(lines)

        # parse groups
        i, split_res = next(obj_split)
        while i < len(lines) and split_res[0] == 'g':
            jawSide = ' '.join(split_res[1:])  # upper/lower
            data_map[jawSide] = {}
            i, split_res = next(obj_split)
            # parse objects
            while i < len(lines) and split_res[0] == 'o':
                toothId = int((' '.join(split_res[1:]))[1:])
                i, split_res = next(obj_split)
                geometry = {'v': [], 'f': [], 'vn': [], 'c': []}

                # parse vertices and faces
                while i < len(lines) and (split_res[0] in {'v', 'f', 'vn'}):
                    vec = self._vector_from_obj_str_split(split_res, len(geometry['v']))
                    if split_res[0] == 'v' and len(vec) == 6:
                        geometry['v'].append(vec[:3])
                        geometry['c'].append(vec[3:])
                    else:
                        geometry[split_res[0]].append(vec)
                    i, split_res = next(obj_split)

                pointsArray = np.asarray(geometry['v'])
                res = vtk.vtkPolyData()
                vtk_points = vtk.vtkPoints()
                vtk_points.SetNumberOfPoints(pointsArray.shape[0])
                for j, point in enumerate(pointsArray.tolist()):
                    vtk_points.SetPoint(j, point)
                res.SetPoints(vtk_points)

                cellsArray = np.asarray(geometry['f'])
                vtk_cells = vtk.vtkCellArray()
                for cell in cellsArray.tolist():
                    vtk_cells.InsertNextCell(len(cell), cell)
                res.SetPolys(vtk_cells)

                # Add and Rotate initial polyData object:
                data_map[jawSide][toothId] = Utilities.rotatePolyData(res, 90, 180)

        if i != len(lines):
            raise ValueError(f'syntax error at line {i}')
        return data_map


#####################################################################################################
#                                              Tests                                                #
#####################################################################################################

class Tests(object):
    CROWNS_OBJ_SCAN_MASK = '_scan_crown.obj'
    UPPER_TEETH = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}
    LOWER_TEETH = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}
    LEFT_TEETH  = {48, 47, 46, 45, 44, 43, 42, 41, 11, 12, 13, 14, 15, 16, 17, 18}
    RIGHT_TEETH = {21, 22, 23, 24, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 38}

    @staticmethod
    def initilize(case_id: str) -> bool:
        Tests.caseId = case_id
        Tests.caseFolder = f'S:/Projects/TEST_DATA/{Tests.caseId}'
        Tests.outFolder = f'{Tests.caseFolder}/automodeling2/out'
        Tests.treatmentPlan = f'{Tests.caseFolder}/Treatment plan_03_2021-05-06-22:37:05.json'

        with os.scandir(os.path.join(Tests.caseFolder, "models")) as dirs:
            files = [entry.path for entry in dirs if os.path.isfile(entry.path)]
        crownObjsFiles = [file for file in files if file.endswith(Tests.CROWNS_OBJ_SCAN_MASK)]

        if 1 == len(crownObjsFiles):
            Tests.objFileName = crownObjsFiles[0]
        else:
            return False

        if not Path(Tests.outFolder).exists():
            Path(Tests.outFolder).mkdir(parents=True, exist_ok=True)
        return True

    # TODO: Move from here
    @staticmethod
    def __visualize_axis(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                         id_symmetry_dict,
                         jaw_type):
        """Visualize axes and contact points

        :param id_mesh_dict: mesh for each crown
        :param id_symmetry_dict: symmetry as loaded from OBJ file
        :param jaw_type: one of "lower"/"upper"
        """
        renderer = vtk.vtkRenderer()
        for tooth_id in id_mesh_dict.keys():
            if jaw_type == 'lower' and tooth_id // 10 in (1, 2):
                continue
            if jaw_type == 'upper' and tooth_id // 10 in (3, 4):
                continue
            input_mapper = vtk.vtkPolyDataMapper()
            input_mapper.SetInputData(id_mesh_dict[tooth_id])
            input_actor = vtk.vtkActor()
            input_actor.GetProperty().SetColor(0.9, 0.9, 0.9)
            input_actor.SetMapper(input_mapper)
            renderer.AddActor(input_actor)
            if tooth_id % 10 in (1, 2, 3, 4):
                print(tooth_id)
                origin = np.asarray(id_symmetry_dict[tooth_id]['origin'])
                angulation_axis = np.asarray(id_symmetry_dict[tooth_id]['angulation_axis'])
                symmetry_axis = np.asarray(id_symmetry_dict[tooth_id]['symmetry_axis'])
                contact_points = id_symmetry_dict[tooth_id]['contact_points']

                vtk_contact_points = vtk.vtkPoints()
                contact_line = vtk.vtkCellArray()
                contact_pd = vtk.vtkPolyData()
                contact_pd.SetPoints(vtk_contact_points)
                contact_pd.SetLines(contact_line)
                left_point_id = vtk_contact_points.InsertNextPoint(
                    contact_points[0])
                right_point_id = vtk_contact_points.InsertNextPoint(
                    contact_points[1])
                line = vtk.vtkLine()
                line.GetPointIds().SetId(0, left_point_id)
                line.GetPointIds().SetId(1, right_point_id)
                contact_line.InsertNextCell(line)
                contact_mapper = vtk.vtkPolyDataMapper()
                contact_mapper.SetInputData(contact_pd)
                contact_actor = vtk.vtkActor()
                contact_actor.GetProperty().SetColor(1.0, 0.0, 0.0)
                contact_actor.GetProperty().SetLineWidth(3)
                contact_actor.SetMapper(contact_mapper)

                left_sphere_source = vtk.vtkSphereSource()
                left_sphere_source.SetCenter(*contact_points[0])
                left_sphere_source.SetRadius(0.3)
                left_sphere_source.Update()
                left_contact_mapper = vtk.vtkPolyDataMapper()
                left_contact_mapper.SetInputData(left_sphere_source.GetOutput())
                left_contact_actor = vtk.vtkActor()
                left_contact_actor.GetProperty().SetColor(0.0, 1.0, 0.0)
                left_contact_actor.SetMapper(left_contact_mapper)

                right_sphere_source = vtk.vtkSphereSource()
                right_sphere_source.SetCenter(*contact_points[1])
                right_sphere_source.SetRadius(0.3)
                right_sphere_source.Update()
                right_contact_mapper = vtk.vtkPolyDataMapper()
                right_contact_mapper.SetInputData(right_sphere_source.GetOutput())
                right_contact_actor = vtk.vtkActor()
                right_contact_actor.GetProperty().SetColor(0.0, 0.0, 1.0)
                right_contact_actor.SetMapper(right_contact_mapper)

                origin_sphere_source = vtk.vtkSphereSource()
                origin_sphere_source.SetCenter(origin)
                origin_sphere_source.SetRadius(0.3)
                origin_sphere_source.Update()
                origin_contact_mapper = vtk.vtkPolyDataMapper()
                origin_contact_mapper.SetInputData(origin_sphere_source.GetOutput())
                origin_contact_actor = vtk.vtkActor()
                origin_contact_actor.GetProperty().SetColor(0.0, 1.0, 0.8)
                origin_contact_actor.SetMapper(origin_contact_mapper)

                line_source = vtk.vtkLineSource()
                line_source.SetPoint1(origin)
                line_source.SetPoint2(origin + 5 * angulation_axis)
                line_source.Update()
                line_source_1 = vtk.vtkLineSource()
                line_source_1.SetPoint1(origin)
                line_source_1.SetPoint2(origin + symmetry_axis * 15)
                line_source_1.Update()
                line_mapper = vtk.vtkPolyDataMapper()
                line_mapper.SetInputData(line_source.GetOutput())
                line_actor = vtk.vtkActor()
                line_actor.GetProperty().SetLineWidth(3)
                line_actor.GetProperty().SetColor(1.0, 0.8, 0.0)
                line_actor.SetMapper(line_mapper)
                line_mapper_1 = vtk.vtkPolyDataMapper()
                line_mapper_1.SetInputData(line_source_1.GetOutput())
                line_actor_1 = vtk.vtkActor()
                line_actor_1.GetProperty().SetLineWidth(3)
                line_actor_1.GetProperty().SetColor(1.0, 0.8, 0.0)
                line_actor_1.SetMapper(line_mapper_1)

                renderer.AddActor(line_actor)
                renderer.AddActor(line_actor_1)
                renderer.AddActor(contact_actor)
                renderer.AddActor(left_contact_actor)
                renderer.AddActor(right_contact_actor)
                renderer.AddActor(origin_contact_actor)

        render_window = vtk.vtkRenderWindow()
        render_window.AddRenderer(renderer)
        render_window.SetSize(1024, 1080)  # TODO:
        interactor = vtk.vtkRenderWindowInteractor()
        interactor.SetRenderWindow(render_window)
        renderer.SetBackground(0.1, 0.2, 0.3)
        render_window.Render()
        interactor.Start()

    @staticmethod
    def __angle_between_vectors(vect1: np.ndarray, vect2: np.ndarray):
        a = np.dot(vect1, vect2)
        b = np.sqrt(np.dot(vect1, vect1)) * np.sqrt(np.dot(vect2, vect2))
        return math.acos(a / b) * 180 / math.pi

    @staticmethod
    def __distance_between_two_points(pt1: np.ndarray, pt2: np.ndarray):
        return math.sqrt(np.square(pt1 - pt2).sum())

    @staticmethod
    def __distance_between_two_points_skipY(pt1: np.ndarray, pt2: np.ndarray):
        pt1[1], pt2[1] = 0, 0
        return math.sqrt(np.square(pt1 - pt2).sum())

    # TODO: Move from here
    @staticmethod
    def _rotate_tooth_along_axis_and_calculate(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                                               symmetry_dict,
                                               features_dict,
                                               tooth_id: int):

        polyData: vtkPolyData = id_mesh_dict[tooth_id]

        # polyDataOrig: vtkPolyData = vtkPolyData()
        # polyDataOrig.DeepCopy(polyData)

        origin = np.asarray(symmetry_dict[tooth_id]['origin'])
        angulation_axis = np.asarray(symmetry_dict[tooth_id]['angulation_axis'])
        symmetry_axis = np.asarray(symmetry_dict[tooth_id]['symmetry_axis'])
        contact_points = symmetry_dict[tooth_id]['contact_points']
        # cutting_eges = features_dict[tooth_id]["cutting_edge"]

        # Calc line between lines: (to rotate against X axe)
        symmetryAxisPt = origin + symmetry_axis * 10
        angulationAxisPt = origin + angulation_axis * 10

        sign = ((origin + symmetry_axis)[1] - origin[1]) / abs((origin + symmetry_axis)[1] - origin[1])
        verticalLinePt = origin + np.asarray([0, sign * 10, 0])
        horizontalLinePt = origin + np.asarray([10, 0, 0])

        # TODO: Refactor to find angle between normals (positive / negative)
        axisPoint, pt2 = verticalLinePt - origin, symmetryAxisPt - origin
        axisPoint[0], pt2[0] = 0, 0  # Discard X coordinates
        xRotateAngle = Tests.__angle_between_vectors(axisPoint, pt2)
        if tooth_id in Tests.LOWER_TEETH:
            xRotateAngle *= -1

        axisPoint, pt2 = horizontalLinePt - origin, angulationAxisPt - origin
        axisPoint[1], pt2[1] = 0, 0  # Discard Y coordinates
        # TODO: Refactor to find angle between normals (positive / negative)
        yRotateAngle = Tests.__angle_between_vectors(axisPoint, pt2)
        # print(f"axisPoint: {axisPoint}, v: {pt2}")
        if axisPoint[2] > pt2[2]:
            yRotateAngle *= -1

        # TODO: Refactor to find angle between normals (positive / negative)
        axisPoint, pt2 = horizontalLinePt - origin, angulationAxisPt - origin
        axisPoint[2], pt2[2] = 0, 0  # Discard z coordinates
        zRotateAngle = Tests.__angle_between_vectors(axisPoint, pt2)
        if pt2[1] > axisPoint[1]:
            zRotateAngle *= -1

        print(f"xRotateAngle: {xRotateAngle}, yRotateAngle: {yRotateAngle}, zRotateAngle: {zRotateAngle}")
        polyData = ToothOrientation.rotatePolyData(polyData, xRotateAngle, yRotateAngle, zRotateAngle)

        angulationAxisActor = Utilities.getLineActorFromPoints(origin, angulationAxisPt)

        symmetryAxisActor = Utilities.getLineActorFromPoints(origin, symmetryAxisPt)
        symmetryAxisActor.GetProperty().SetColor(1, 0, 0)

        targetLineActor = Utilities.getLineActorFromPoints(origin, verticalLinePt)
        targetLineActor.GetProperty().SetColor(0, 0, 1)

        # Bounding box:
        outlineFilter: vtkOutlineFilter = vtkOutlineFilter()
        outlineFilter.SetInputData(polyData)

        outlineMapper: vtkPolyDataMapper = vtkPolyDataMapper()
        outlineMapper.SetInputConnection(outlineFilter.GetOutputPort())

        outlineActor: vtkActor = vtkActor()
        outlineActor.SetMapper(outlineMapper)
        outlineActor.GetProperty().SetColor(1.0, 0.0, 0.0);

        # cuttingEgesActor: vtkActor = Utilities.getPointsActorNumpy(cutting_eges)

        toothActor: vtkActor = Utilities.getPolyDataActor(polyData)
        toothActor.GetProperty().SetColor(0.9, 0.9, 0.9)

        '''
        obbTree = vtkOBBTree()
        obbTree.SetDataSet(polyDataOrig)
        obbTree.SetMaxLevel(1)
        obbTree.BuildLocator()

        treeData: vtkPolyData = vtkPolyData()
        obbTree.GenerateRepresentation(0, treeData);

        obbActor = Utilities.getPolyDataActor(treeData)
        obbActor.GetProperty().SetOpacity(.5);
        '''

        Utilities.DisplayActors([toothActor,
                                 outlineActor,
                                 # obbActor,
                                 # angulationAxisActor,
                                 # symmetryAxisActor,
                                 # targetLineActor,
                                 # cuttingEgesActor
                                 ])

    @staticmethod
    def get_orientation_angels(angulation_axis: np.ndarray,
                               symmetry_axis: np.ndarray):
        sign = symmetry_axis[1] / abs(symmetry_axis[1])  # HACK: get Y coordinate sign
        point_vertical = np.asarray([0, sign * 1, 0])
        point_horizontal = np.asarray([1, 0, 0])

        '''
        Utilities.DisplayActors([
            Utilities.getLineActorFromPoints(origin, verticalLinePt),
            Utilities.getLineActorFromPoints(origin, horizontalLinePt, [1,0,0]),
        ])
        print(xRotateAngle)
        Utilities.DisplayActors([
            Utilities.getLineActorFromPoints([0, 0, 0], axisPoint),
            Utilities.getLineActorFromPoints([0, 0, 0], ptTooth, [1,0,0]),
        ])
        '''

        axisPoint, ptTooth = point_vertical, symmetry_axis * np.asarray([0, 1, 1])
        xRotateAngle = Tests.__angle_between_vectors(axisPoint, ptTooth)
        xRotateAngle *= -1 if axisPoint[1] > ptTooth[1] else 1

        axisPoint, ptTooth = point_horizontal, angulation_axis * np.asarray([1, 0, 1])
        yRotateAngle = Tests.__angle_between_vectors(axisPoint, ptTooth)
        yRotateAngle *= -1 if axisPoint[2] > ptTooth[2] else 1

        axisPoint, ptTooth = point_horizontal, angulation_axis * np.asarray([1, 1, 0])
        zRotateAngle = Tests.__angle_between_vectors(axisPoint, ptTooth)
        zRotateAngle *= -1 if ptTooth[1] > axisPoint[1] else 1

        return xRotateAngle, yRotateAngle, zRotateAngle

    @staticmethod
    def orient_single_tooth_and_visualize(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                                          symmetry_dict: Dict,
                                          tooth_id: int):
        polyData: vtkPolyData = id_mesh_dict[tooth_id]
        origin = np.asarray(symmetry_dict[tooth_id]['origin'])
        angulation_axis = np.asarray(symmetry_dict[tooth_id]['angulation_axis'])
        symmetry_axis = np.asarray(symmetry_dict[tooth_id]['symmetry_axis'])

        xRotateAngle, yRotateAngle, zRotateAngle = Tests.get_orientation_angels(angulation_axis, symmetry_axis)
        print(f"xRotateAngle: {xRotateAngle}, yRotateAngle: {yRotateAngle}, zRotateAngle: {zRotateAngle}")

        Utilities.visualize(polyData, True)

        polyData = ToothOrientation.rotatePolyData(polyData, xRotateAngle, yRotateAngle, zRotateAngle)

        angulationAxisActor = Utilities.getLineActorFromPoints(origin, origin + angulation_axis * 15)
        symmetryAxisActor = Utilities.getLineActorFromPoints(origin, origin + symmetry_axis * 15)
        symmetryAxisActor.GetProperty().SetColor(1, 0, 0)

        minDist, angle = 1000, 0
        for angleToRotate in range(-15, 15, 1):
            data = ToothOrientation.rotatePolyData(polyData, 0, 0, angleToRotate)
            bounds = data.GetBounds()
            xDistance = bounds[1] - bounds[0]
            if minDist > xDistance:
                minDist, angle = xDistance, angleToRotate

        print(f'Additional angle = {angle}')
        polyData = ToothOrientation.rotatePolyData(polyData, 0, 0, angle)

        # Bounding box actor:
        outlineActor: vtkActor = Utilities.getOutlineActor(polyData)

        toothActor: vtkActor = Utilities.getPolyDataActor(polyData)
        toothActor.GetProperty().SetColor(0.9, 0.9, 0.9)

        # sign = symmetry_axis[1] / abs(symmetry_axis[1])  # HACK: get Y coordinate sign
        # horizontalLinePt = origin + np.asarray([10, 0, 0])
        # targetLineActor = Utilities.getLineActorFromPoints(origin, origin + np.asarray([0, sign * 10, 0]), [0, 0, 1])

        Utilities.DisplayActors([toothActor, outlineActor,
                                 # angulationAxisActor, symmetryAxisActor,
                                 # targetLineActor,
                                 ])

    @staticmethod
    def orient_single_tooth(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                            symmetry_dict: Dict,
                            tooth_id: int):
        polyData: vtkPolyData = id_mesh_dict[tooth_id]
        angulation_axis = np.asarray(symmetry_dict[tooth_id]['angulation_axis'])
        symmetry_axis = np.asarray(symmetry_dict[tooth_id]['symmetry_axis'])

        xRotateAngle, yRotateAngle, zRotateAngle = Tests.get_orientation_angels(angulation_axis, symmetry_axis)
        polyData = ToothOrientation.rotatePolyData(polyData, xRotateAngle, yRotateAngle, zRotateAngle)

        minDist, angle = 1000, 0
        for angleToRotate in range(-15, 15, 1):
            data = ToothOrientation.rotatePolyData(polyData, 0, 0, angleToRotate)
            bounds = data.GetBounds()
            xDistance = bounds[1] - bounds[0]
            if minDist > xDistance:
                minDist, angle = xDistance, angleToRotate

        print(f'tooth_id = {tooth_id}, Additional angle = {angle}')
        return ToothOrientation.rotatePolyData(polyData, 0, 0, angle)



    # TODO: Move from here
    @staticmethod
    def __calc_and_visualize_tooth_lengths(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                                           id_symmetry_dict,
                                           tooth_id: int):
        lowerTeeth = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}
        rightTeeth = {21, 22, 23, 24, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 38}

        polyData: vtkPolyData = id_mesh_dict[tooth_id]

        origin = np.asarray(id_symmetry_dict[tooth_id]['origin'])
        angulation_axis = np.asarray(id_symmetry_dict[tooth_id]['angulation_axis'])
        symmetry_axis = np.asarray(id_symmetry_dict[tooth_id]['symmetry_axis'])

        # Calc line between lines: (to rotate against X axe)
        symmetryAxisPt = origin + symmetry_axis * 15
        angulationAxisPt = origin + angulation_axis * 15

        sign = ((origin + symmetry_axis)[1] - origin[1]) / abs((origin + symmetry_axis)[1] - origin[1])
        verticalLinePt = origin + np.asarray([0, sign * 30, 0])
        horizontalLinePt = origin + np.asarray([10, 0, 0])

        pt1, pt2 = verticalLinePt - origin, symmetryAxisPt - origin
        pt1[0], pt2[0] = 0, 0  # Discard X coordinates
        xRotateAngle = Tests.__angle_between_vectors(pt1, pt2)

        pt1, pt2 = horizontalLinePt - origin, angulationAxisPt - origin
        pt1[1], pt2[1] = 0, 0  # Discard Y coordinates
        yRotateAngle = Tests.__angle_between_vectors(pt1, pt2)

        if tooth_id in lowerTeeth:
            xRotateAngle *= -1
        if tooth_id in rightTeeth:
            yRotateAngle *= -1

        # Rotate polydata:
        # TODO: Remove --> we need borders only
        transform: vtkTransform = vtkTransform()
        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        # transform.RotateX(xRotateAngle)
        # transform.RotateY(yRotateAngle)

        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
        transformFilter.Update()
        polyData = transformFilter.GetOutput()

        input_mapper = vtk.vtkPolyDataMapper()
        input_mapper.SetInputData(polyData)
        input_actor = vtk.vtkActor()
        input_actor.GetProperty().SetColor(0.9, 0.9, 0.9)
        input_actor.SetMapper(input_mapper)

        # Bounding box:
        outlineFilter: vtkOutlineFilter = vtkOutlineFilter()
        outlineFilter.SetInputData(polyData)

        outlineMapper: vtkPolyDataMapper = vtkPolyDataMapper()
        outlineMapper.SetInputConnection(outlineFilter.GetOutputPort())

        outlineActor: vtkActor = vtkActor()
        outlineActor.SetMapper(outlineMapper)
        outlineActor.GetProperty().SetColor(1.0, 0.0, 0.0);

        Utilities.DisplayActors([input_actor, outlineActor])

    @staticmethod
    def CalculateAndDisplay():
        # readersTests = ReadersTests()
        # readersTests.read_stl_test()

        # PointsTests.Test()
        # LinesTests.DisplayLine()

        tests = ToothReader(Tests.objFileName)

        upperTeeth: Dict[int, vtkPolyData] = tests.upperTeeth;
        tooth14, tooth24 = upperTeeth[14], upperTeeth[24]
        tooth16, tooth26 = upperTeeth[16], upperTeeth[26]

        center14, center24 = Point3D(tooth14.GetCenter()), Point3D(tooth24.GetCenter())
        center16, center26 = Point3D(tooth16.GetCenter()), Point3D(tooth26.GetCenter())

        actorPoints14_24: vtkActor = Utilities.getPointsActor([center14, center24])
        actorPoints16_26: vtkActor = Utilities.getPointsActor([center16, center26])
        actorLine14_24: vtkActor = Utilities.getLineActor(Line3D(center14, center24))
        actorLine16_26: vtkActor = Utilities.getLineActor(Line3D(center16, center26))

        upper: List[vtkPolyData] = [data for _, data in upperTeeth.items()]
        upperToothActor: vtkActor = Utilities.getPolyDataActor(Utilities.appendPolyData(upper))

        Utilities.DisplayActors([
            actorPoints14_24, actorPoints16_26,
            actorLine14_24, actorLine16_26,
            upperToothActor
        ])

    @staticmethod
    def getMissingTeeth(treatmentPlanFile: str) -> Set[int]:
        with open(treatmentPlanFile) as json_file:
            jsonObject: Dict = json.load(json_file)

        modelling_data = jsonObject.get('modellingData', None)
        existing_teeth = set([int(k) for k, v in modelling_data.items()])
        all_teeth = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28,
                     48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}

        return list(all_teeth.difference(existing_teeth))

    @staticmethod
    def getMissingTeethTest():
        missingTeeth: Set[int] = Tests.getMissingTeeth(Tests.treatmentPlan)
        print(missingTeeth)

    @staticmethod
    def ProcessModels():
        tests = ToothReader(Tests.objFileName)
        features_dict = ExtractFeatures(tests.teethMap)
        symmetry_dict = GetSymmetryAxis(tests.teethMap, features_dict)

        # Utilities.visualize(Utilities.appendPolyData([data for _, data in tests.teethMap.items()]))

        # Save extracted features, axes and contact points to JSON files
        save_features(os.path.join(Tests.outFolder, f'features_{Tests.caseId}.json'), tests.teethMap,
                      features_dict)
        json.dump(symmetry_dict, open(os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json'), 'wt'))

        Tests.__visualize_axis(tests.teethMap, symmetry_dict, jaw_type="upper")
        Tests.__visualize_axis(tests.teethMap, symmetry_dict, jaw_type="lower")

    @staticmethod
    def Visualize_Axis_Tests():
        symmetryFile = os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json')
        tests = ToothReader(Tests.objFileName)
        with open(symmetryFile) as jsonData:
            tmp = json.loads(jsonData.read())
            symmetry_dict = {int(k): v for k, v in tmp.items()}

        Tests.__visualize_axis(tests.teethMap, symmetry_dict, jaw_type="upper")
        Tests.__visualize_axis(tests.teethMap, symmetry_dict, jaw_type="lower")

    @staticmethod
    def RotateToothAlongAxis():
        symmetryFile = os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json')
        featuresFile = os.path.join(Tests.outFolder, f'features_{Tests.caseId}.json')
        tests = ToothReader(Tests.objFileName)
        with open(symmetryFile) as jsonData:
            tmp = json.loads(jsonData.read())
            symmetry_dict = {int(k): v for k, v in tmp.items()}
        with open(featuresFile) as jsonData:
            tmp = json.loads(jsonData.read())
            features_dict = {int(k): v for k, v in tmp.items()}

        for tooth_id in [11, 12, 13, 21, 22, 23, 31, 32, 33, 41, 42, 43]:
            # for tooth_id in [11, 12, 13, 14, 21, 22, 23, 24]:
            # for tooth_id in [31, 32, 33, 34, 41, 42, 43, 44]:
            # for tooth_id in [21]:
            Tests._rotate_tooth_along_axis_and_calculate(tests.teethMap, symmetry_dict, features_dict, tooth_id)

    @staticmethod
    def CalculateLengthsWithOrientedBoundingBox():
        tests = ToothReader(Tests.objFileName)
        # upperTeeth = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}
        # lowerTeeth = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}

        tooth_id = 22
        polyData: vtkPolyData = tests.teethMap[tooth_id]

        obbTree = vtkOBBTree()
        obbTree.SetDataSet(polyData)
        obbTree.SetMaxLevel(1)
        obbTree.BuildLocator()

        treeData: vtkPolyData = vtkPolyData()
        obbTree.GenerateRepresentation(0, treeData);

        toothActor: vtkActor = Utilities.getPolyDataActor(polyData)
        obbActor = Utilities.getPolyDataActor(treeData)
        obbActor.GetProperty().SetOpacity(.5);

        Utilities.DisplayActors([obbActor, toothActor])

    @staticmethod
    def CutToothAlongExis_ManyPlanes():
        symmetryFile = os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json')
        tests = ToothReader(Tests.objFileName)
        with open(symmetryFile) as jsonData:
            tmp = json.loads(jsonData.read())
            symmetry_dict = {int(k): v for k, v in tmp.items()}

        upperTeeth = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}
        lowerTeeth = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}

        tooth_id = 44
        polyData: vtkPolyData = tests.teethMap[tooth_id]

        bounds = polyData.GetBounds()
        center = polyData.GetCenter()

        origin = np.asarray(symmetry_dict[tooth_id]['origin'])
        angulation_axis = np.asarray(symmetry_dict[tooth_id]['angulation_axis'])
        symmetry_axis = np.asarray(symmetry_dict[tooth_id]['symmetry_axis'])
        contact_points = symmetry_dict[tooth_id]['contact_points']

        start = bounds[2] - center[1]
        end = bounds[3] - center[1]
        '''
        if tooth_id in lowerTeeth:
            start, end = 0, bounds[3] - center[1]
        else:
            start, end = bounds[2] - center[1], 0
        '''

        plane: vtkPlane = vtkPlane()
        plane.SetOrigin(center)
        # plane.SetNormal(symmetry_axis)
        plane.SetNormal(0, 1, 0)

        cutter: vtkCutter = vtkCutter()
        cutter.SetCutFunction(plane)
        cutter.SetInputData(polyData)
        cutter.GenerateValues(30, start, end)
        cutter.Update()

        plane1: vtkPlane = vtkPlane()
        plane1.SetOrigin(center)
        # plane1.SetNormal(symmetry_axis)
        plane1.SetNormal(1, 0, 0)

        cutter1: vtkCutter = vtkCutter()
        cutter1.SetCutFunction(plane1)
        cutter1.SetInputData(cutter.GetOutput())
        cutter1.GenerateValues(30, start, end)
        cutter1.Update()

        # ptsActor: vtkActor = Utilities.getPointsActorNumpy([center, ])
        toothActor: vtkActor = Utilities.getPolyDataActor(polyData)

        cutterActor1: vtkActor = Utilities.getPolyDataActor(cutter.GetOutput())
        cutterActor1.GetProperty().SetColor(1.0, 0.0, 0.0)
        cutterActor1.GetProperty().SetLineWidth(2)

        cutterActor2: vtkActor = Utilities.getPolyDataActor(cutter1.GetOutput())
        cutterActor2.GetProperty().SetColor(0.0, 1.0, 0.0)
        cutterActor2.GetProperty().SetLineWidth(3)

        Utilities.DisplayActors([cutterActor1, cutterActor2])

    @staticmethod
    def Calc_And_Visualize_Tooth_Lengths():
        symmetryFile = os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json')
        tests = ToothReader(Tests.objFileName)
        with open(symmetryFile) as jsonData:
            tmp = json.loads(jsonData.read())
            symmetry_dict = {int(k): v for k, v in tmp.items()}

        for tooth_id in [11, 12, 13, 14, 21, 22, 23, 24, 31, 32, 33, 34, 41, 42, 43, 44]:
            Tests.__calc_and_visualize_tooth_lengths(tests.teethMap, symmetry_dict, tooth_id)

    @staticmethod
    def Orinent_And_Calculate_Tooth_Length():
        reader = ToothReader(Tests.objFileName)
        orientator = ToothOrientation()

        for toothId in [11, 12, 13, 21, 22, 23, 31, 32, 33]:
            Utilities.writeStl(reader.teethMap[toothId], f'/home/andtokm/Projects/data/out/Tooths/{toothId}_tooth.stl')
            tooth = reader.teethMap[toothId]

            tooth = orientator.OrientTooth(tooth, toothId)
            Utilities.visualize(tooth, True)

    @staticmethod
    def OrientToothAlongAxis():
        symmetryFile = os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json')
        tests = ToothReader(Tests.objFileName)
        with open(symmetryFile) as jsonData:
            tmp = json.loads(jsonData.read())
            symmetry_dict = {int(k): v for k, v in tmp.items()}


        # for tooth_id in [11, 12, 13, 21, 22, 23, 31, 32, 33, 41, 42, 43]:
         # for tooth_id in [11, 12, 13, 14, 21, 22, 23, 24]:
        # for tooth_id in [31, 32, 33, 34, 41, 42, 43, 44]:
        for tooth_id in [11]:
            Tests.orient_single_tooth_and_visualize(tests.teethMap, symmetry_dict, tooth_id)

    @staticmethod
    def AddToothMeasurmentsData(polyData: vtkPolyData) -> vtkPolyData:
        ptCenter: np.array = np.asarray(polyData.GetCenter())
        bounds: np.array = np.asarray(polyData.GetBounds())

        xLength: float = bounds[1] - bounds[0]
        yLength: float = bounds[3] - bounds[2]
        zLength: float = bounds[5] - bounds[4]

        xLeftBottomPoint: np.array = ptCenter - np.array([xLength / 2, -7, 0])
        xRightBottomPoint: np.array = ptCenter + np.array([xLength / 2, 7, 0])

        xLeftTopPoint: np.array = ptCenter - np.array([xLength / 2, 7, 0])
        xRightTopPoint: np.array = ptCenter + np.array([xLength / 2, -7, 0])

        leftLine: vtkLineSource = vtkLineSource()
        leftLine.SetPoint1(xLeftBottomPoint)
        leftLine.SetPoint2(xLeftTopPoint)
        leftLine.Update()

        rightLine: vtkLineSource = vtkLineSource()
        rightLine.SetPoint1(xRightBottomPoint)
        rightLine.SetPoint2(xRightTopPoint)
        rightLine.Update()

        return Utilities.appendPolyData([polyData, leftLine.GetOutput(), rightLine.GetOutput()])

    @staticmethod
    def getTextActor2D(text: str,
                       position: List = [0, 1],
                       color: List = [0, 1, 0],
                       bold: bool = False,
                       fontSize: int = 16) -> vtkActor:
        actor: vtkTextActor = vtkTextActor()
        actor.SetInput(text)
        actor.SetPosition(position)
        actor.GetTextProperty().SetBold(bold)
        actor.GetTextProperty().SetFontSize(fontSize)
        actor.GetTextProperty().SetColor(color)
        return actor

    @staticmethod
    def GetArrowLine_Actors(pt1: List,
                            pt2: List,
                            color: List = [0, 1, 0]) -> vtkPolyData:
        pt1 = np.asarray(pt1)
        pt2 = np.asarray(pt2)

        cone1 = vtkConeSource()
        cone1.SetHeight(2.0)
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
        cone2.SetHeight(2.0)
        cone2.SetRadius(0.05)
        cone2.SetAngle(9)
        cone2.SetResolution(9)
        cone2.SetCenter(pt1)
        cone2.SetDirection(pt1 - pt2)
        cone2.Update()

        bounds2 = cone2.GetOutput().GetBounds()
        cone2.SetCenter(pt1 + np.array([(bounds2[1] - bounds2[0]) / 2, 0, 0]))
        cone2.Update()

        pt1 += np.array([(bounds1[1] - bounds1[0]) / 2, 0, 0])
        pt2 -= np.array([(bounds2[1] - bounds2[0]) / 2, 0, 0])

        lineActor: vtkActor = Utilities.getLineActorFromPoints(pt1, pt2)
        lineActor.GetProperty().SetLineWidth(1)

        coneActor: vtkActor = Utilities.getPolyDataListActor([cone1.GetOutput(), cone2.GetOutput()])
        coneActor.GetProperty().SetColor(0, 0, 1)

        return [lineActor, coneActor]

    @staticmethod
    def OrientToothAlongAxis_AndDisplayFirst_8_Tooths():
        symmetryFile = os.path.join(Tests.outFolder, f'symmetry_{Tests.caseId}.json')
        tests = ToothReader(Tests.objFileName)
        with open(symmetryFile) as jsonData:
            tmp = json.loads(jsonData.read())
            symmetry_dict = {int(k): v for k, v in tmp.items()}

        teethMap: Dict[int, vtkPolyData] = tests.teethMap
        lowerTeethMap: Dict[int, vtkPolyData] = tests.lowerTeeth
        upperTeethMap: Dict[int, vtkPolyData] = tests.upperTeeth

        upperIds = [14, 13, 12, 11, 21, 22, 23, 24]
        lowerIds = [34, 33, 32, 31, 41, 42, 43, 44]

        upperIncisorsLength: float = 0
        lowerIncisorsLength: float = 0
        anteriorUpper: float = 0
        anteriorLower: float = 0

        ###################################### LOWER TEETH ALIGNING ###############################################

        alignedToothActors: List[vtkActor] = []
        xMaxLen, yMaxLen, teeth_alligned = 0.0, 0.0, []
        for tooth_id in upperIds:
            data = Tests.orient_single_tooth(teethMap, symmetry_dict, tooth_id)
            teeth_alligned.append(data)
            bounds: np.array = np.asarray(data.GetBounds())

            xLength: float = bounds[1] - bounds[0]
            xMaxLen = xLength if xLength > xMaxLen else xMaxLen

            yLength: float = bounds[3] - bounds[2]
            yMaxLen = yLength if yLength > yMaxLen else yMaxLen

            anteriorUpper += xLength if tooth_id not in [14, 24] else 0
            upperIncisorsLength += xLength if tooth_id in [11, 12, 21, 22] else 0

        xMaxLen += 0.5
        xPos = -xMaxLen * len(upperIds) / 2
        teethAlignedUpperTeeth = []
        for data in teeth_alligned:
            data = ToothOrientation.setPolyDataCenter(data, xPos, 0, 0)
            # data = Tests.AddToothMeasurmentsData(data)
            teethAlignedUpperTeeth.append(data)
            xPos += xMaxLen

            ptCenter: np.array = np.asarray(data.GetCenter())
            bounds: np.array = np.asarray(data.GetBounds())

            xLength: float = bounds[1] - bounds[0]
            xLeftPoint: np.array = ptCenter - np.array([xLength / 2, 0, 0])
            xRightPoint: np.array = ptCenter + np.array([xLength / 2, 0, 0])

            # Points actors:
            ptActor = Utilities.getPointsActor([xLeftPoint, xRightPoint])
            ptActor.GetProperty().SetPointSize(4)
            # ptsActors.append(ptActor)

            # Vertical lines actors:
            xLeftBottomPoint: np.array = ptCenter - np.array([xLength / 2, -yMaxLen / 2, 0])
            xRightBottomPoint: np.array = ptCenter + np.array([xLength / 2, yMaxLen / 2, 0])

            xLeftTopPoint: np.array = ptCenter - np.array([xLength / 2, yMaxLen / 2 + 1.5, 0])
            xRightTopPoint: np.array = ptCenter + np.array([xLength / 2, -yMaxLen / 2 - 1.5, 0])

            l1Actor = Utilities.getLineActorFromPoints(xLeftBottomPoint, xLeftTopPoint, [0.6, 0.6, 0.4], 1)
            l1Actor.GetProperty().SetLineWidth(2)
            l2Actor = Utilities.getLineActorFromPoints(xRightBottomPoint, xRightTopPoint, [0.6, 0.6, 0.4], 1)
            l2Actor.GetProperty().SetLineWidth(2)

            # Size lines actors:
            lineLeftPoint: np.array = ptCenter - np.array([xLength / 2, yMaxLen / 2, 0])
            rightLeftPoint: np.array = ptCenter + np.array([xLength / 2, -yMaxLen / 2, 0])
            l3Actors = Tests.GetArrowLine_Actors(lineLeftPoint, rightLeftPoint, [1.0, 0.0, 0])

            alignedToothActors.extend([l1Actor, l2Actor])
            alignedToothActors.extend(l3Actors)

        alignedUpperTeethActor = Utilities.getPolyDataActor(Utilities.appendPolyData(teethAlignedUpperTeeth))
        alignedToothActors.append(alignedUpperTeethActor)

        ###################################### UPPER TEETH ALIGNING ###############################################

        xMaxLen, yMaxLen, teeth_alligned = 0.0, 0.0, []
        for tooth_id in lowerIds:
            data = Tests.orient_single_tooth(teethMap, symmetry_dict, tooth_id)
            teeth_alligned.append(data)
            bounds: np.array = np.asarray(data.GetBounds())

            xLength: float = bounds[1] - bounds[0]
            xMaxLen = xLength if xLength > xMaxLen else xMaxLen
            anteriorLower += xLength if tooth_id not in [34, 44] else 0
            lowerIncisorsLength += xLength if tooth_id in [31, 32, 41, 42] else 0

            yLength: float = bounds[3] - bounds[2]
            yMaxLen = yLength if yLength > yMaxLen else yMaxLen

        xMaxLen += 0.5
        xPos = -xMaxLen * len(upperIds) / 2
        teethAlignedLowerTeeth = []
        for data in teeth_alligned:
            data = ToothOrientation.setPolyDataCenter(data, xPos, -15, 0)
            # data = Tests.AddToothMeasurmentsData(data)
            teethAlignedLowerTeeth.append(data)
            xPos += xMaxLen

            ptCenter: np.array = np.asarray(data.GetCenter())
            bounds: np.array = np.asarray(data.GetBounds())

            xLength: float = bounds[1] - bounds[0]
            xLeftPoint: np.array = ptCenter - np.array([xLength / 2, 0, 0])
            xRightPoint: np.array = ptCenter + np.array([xLength / 2, 0, 0])

            # Points actors:
            ptActor = Utilities.getPointsActor([xLeftPoint, xRightPoint])
            ptActor.GetProperty().SetPointSize(4)
            # ptsActors.append(ptActor)

            # Vertical lines actors:
            xLeftBottomPoint: np.array = ptCenter - np.array([xLength / 2, -yMaxLen / 2 - 1, 0])
            xRightBottomPoint: np.array = ptCenter + np.array([xLength / 2, yMaxLen / 2 + 1, 0])

            xLeftTopPoint: np.array = ptCenter - np.array([xLength / 2, yMaxLen / 2, 0])
            xRightTopPoint: np.array = ptCenter + np.array([xLength / 2, -yMaxLen / 2, 0])

            l1Actor = Utilities.getLineActorFromPoints(xLeftBottomPoint, xLeftTopPoint, [0.6, 0.6, 0.4], 1)
            l1Actor.GetProperty().SetLineWidth(2)
            l2Actor = Utilities.getLineActorFromPoints(xRightBottomPoint, xRightTopPoint, [0.6, 0.6, 0.4], 1)
            l2Actor.GetProperty().SetLineWidth(2)

            # Size lines actors:
            lineLeftPoint: np.array = ptCenter - np.array([xLength / 2, -yMaxLen / 2, 0])
            rightLeftPoint: np.array = ptCenter + np.array([xLength / 2, yMaxLen / 2, 0])
            l3Actors = Tests.GetArrowLine_Actors(lineLeftPoint, rightLeftPoint, [1.0, 0.0, 0])

            alignedToothActors.extend([l1Actor, l2Actor])
            alignedToothActors.extend(l3Actors)

        alignedLowerTeethActor = Utilities.getPolyDataActor(Utilities.appendPolyData(teethAlignedLowerTeeth))
        alignedToothActors.append(alignedLowerTeethActor)

        ###################################### JAWs ###############################################

        jawsActor: List[vtkActor] = []
        for tooth_id, data in upperTeethMap.items():
            data = ToothOrientation.rotatePolyData(data, -90, 180, 0)
            ptCenter: np.array = np.asarray(data.GetCenter())
            data = ToothOrientation.setPolyDataCenter(data, ptCenter[0] + 30, ptCenter[1] + 40, ptCenter[2])
            upperTeethMap[tooth_id] = data

        for tooth_id, data in lowerTeethMap.items():
            data = ToothOrientation.rotatePolyData(data, 90, 0, 0)
            ptCenter: np.array = np.asarray(data.GetCenter())
            data = ToothOrientation.setPolyDataCenter(data, ptCenter[0] - 30, ptCenter[1] + 40, ptCenter[2])
            lowerTeethMap[tooth_id] = data

        lowerTeethPolyData = Utilities.appendPolyData([data for _, data in lowerTeethMap.items()])
        jawsActor.append(Utilities.getPolyDataActor(lowerTeethPolyData))

        upperTeethPolyData = Utilities.appendPolyData([data for _, data in upperTeethMap.items()])
        jawsActor.append(Utilities.getPolyDataActor(upperTeethPolyData))

        premolarDistanceUpperActual, molarDistanceUpperActual = None, None
        premolarDistanceLowerActual, molarDistanceLowerActual = None, None

        if 14 in upperTeethMap.keys() and 24 in upperTeethMap.keys():
            firstTooth, secondTooth = upperTeethMap[14], upperTeethMap[24]
            ptCenter1, ptCenter2 = np.asarray(firstTooth.GetCenter()), np.asarray(secondTooth.GetCenter())

            pointsActor: vtkActor = Utilities.getPointsActor([ptCenter1, ptCenter2])
            linesActor: vtkActor = Utilities.getLineActorFromPoints(ptCenter1, ptCenter2, color=[0.43, 0.20, 0.4])

            premolarDistanceUpperActual: float = Tests.__distance_between_two_points_skipY(ptCenter1, ptCenter2)
            jawsActor.extend([pointsActor, linesActor])

        if 16 in upperTeethMap.keys() and 26 in upperTeethMap.keys():
            firstTooth, secondTooth = upperTeethMap[16], upperTeethMap[26]
            ptCenter1, ptCenter2 = np.asarray(firstTooth.GetCenter()), np.asarray(secondTooth.GetCenter())

            pointsActor: vtkActor = Utilities.getPointsActor([ptCenter1, ptCenter2])
            linesActor: vtkActor = Utilities.getLineActorFromPoints(ptCenter1, ptCenter2, color=[0.43, 0.20, 0.4])

            molarDistanceUpperActual: float = Tests.__distance_between_two_points_skipY(ptCenter1, ptCenter2)
            jawsActor.extend([pointsActor, linesActor])

        if 34 in lowerTeethMap.keys() and 44 in lowerTeethMap.keys():
            firstTooth, secondTooth = lowerTeethMap[34], lowerTeethMap[44]
            ptCenter1, ptCenter2 = np.asarray(firstTooth.GetCenter()), np.asarray(secondTooth.GetCenter())

            borders1: np.ndarray = np.asarray(firstTooth.GetBounds())
            borders2: np.ndarray = np.asarray(secondTooth.GetBounds())

            firstToothXLen, secondToothXLen = borders1[1] - borders1[0], borders2[1] - borders2[0]
            firstToothYLen, secondToothYLen = borders1[3] - borders1[2], borders2[3] - borders2[2]

            ptCenter1[0] += 1
            ptCenter2[0] -= 1
            ptCenter1[1] += firstToothYLen * 0.45
            ptCenter2[1] += secondToothYLen * 0.45

            pt1, pt2 = ptCenter1, ptCenter2
            pointsActor: vtkActor = Utilities.getPointsActor([pt1, pt2])
            linesActor: vtkActor = Utilities.getLineActorFromPoints(pt1, pt2, color=[0.43, 0.20, 0.4])

            premolarDistanceLowerActual: float = Tests.__distance_between_two_points_skipY(pt1, pt2)
            jawsActor.extend([pointsActor, linesActor])

        if 36 in lowerTeethMap.keys() and 46 in lowerTeethMap.keys():
            firstTooth, secondTooth = lowerTeethMap[36], lowerTeethMap[46]
            ptCenter1, ptCenter2 = np.asarray(firstTooth.GetCenter()), np.asarray(secondTooth.GetCenter())

            borders1: np.ndarray = np.asarray(firstTooth.GetBounds())
            borders2: np.ndarray = np.asarray(secondTooth.GetBounds())

            firstToothXLen, secondToothXLen = borders1[1] - borders1[0], borders2[1] - borders2[0]
            firstToothYLen, secondToothYLen = borders1[3] - borders1[2], borders2[3] - borders2[2]

            ptCenter1[0] += 1.5
            ptCenter2[0] -= 1.5
            ptCenter1[1] += firstToothYLen * 0.45
            ptCenter2[1] += secondToothYLen * 0.45

            pt1, pt2 = ptCenter1, ptCenter2
            pointsActor: vtkActor = Utilities.getPointsActor([pt1, pt2])
            linesActor: vtkActor = Utilities.getLineActorFromPoints(pt1, pt2, color=[0.43, 0.20, 0.4])

            molarDistanceLowerActual: float = Tests.__distance_between_two_points_skipY(ptCenter1, ptCenter2)
            jawsActor.extend([pointsActor, linesActor])

        premolarDistanceExpected: float = upperIncisorsLength * 100.0 / 85.0
        molarDistanceExpected: float = upperIncisorsLength * 100.0 / 65.0
        anteriorRatio: float = anteriorLower / anteriorUpper * 100.0

        #################################### Measurements and Text info #########################################

        textsActors: List[vtkActor] = []
        yPos = 320
        iActor1: vtkActor = Tests.getTextActor2D(f'Upper incisors Length:', [10, yPos], [0.63, 0.7, 0])
        iActor2: vtkActor = Tests.getTextActor2D(f'{round(upperIncisorsLength, 2)}'.format(), [190, yPos], [1, 1, 1])

        yPos -= 25
        delimiter0 = Tests.getTextActor2D(f'_______________________________________________',
                                          [10, yPos], [1, 1, 1], bold=True)
        yPos -= 25

        iActor0: vtkActor = Tests.getTextActor2D(f'Actual    Expected', [185, yPos], [1, 1, 1], fontSize=15)
        yPos -= 10

        delimiter = Tests.getTextActor2D(f'_______________________________________________',
                                         [10, yPos], [1, 1, 1], bold=True)
        yPos -= 25

        actor1 = Tests.getTextActor2D(f'Bolton measurements:', [10, yPos], [0.63, 0.7, 0], bold=True)
        yPos -= 25

        actor2: vtkActor = Tests.getTextActor2D(f'Anterior ratio:', [40, yPos], [1, 1, 1])
        actor3: vtkActor = Tests.getTextActor2D(f'{round(anteriorRatio, 2)}', [190, yPos], [1, 1, 1])
        actor4: vtkActor = Tests.getTextActor2D(f'(Average 77.20%)', [250, yPos], [0, 1, 0])
        yPos -= 25

        textsActors.extend([delimiter0, delimiter, iActor0, iActor1, iActor2, actor1, actor2, actor3, actor4])

        delimiter = Tests.getTextActor2D(f'_______________________________________________',
                                         [10, yPos], [1, 1, 1], bold=True)
        textsActors.append(delimiter)

        yPos -= 25
        if premolarDistanceUpperActual:
            actor1 = Tests.getTextActor2D(f'Upper (Pont method):', [10, yPos], [0.63, 0.7, 0], bold=True)
            yPos -= 25
            actor2 = Tests.getTextActor2D(f'Premolar distance:', [40, yPos], [1, 1, 1])
            actor3 = Tests.getTextActor2D(f'{round(premolarDistanceUpperActual, 2)}', [190, yPos], [1, 1, 1])
            actor4 = Tests.getTextActor2D(f' / ', [230, yPos], [1, 1, 1])
            actor5 = Tests.getTextActor2D(f'{round(premolarDistanceExpected, 2)}', [250, yPos], [0, 1, 0])
            yPos -= 25
            textsActors.extend([actor1, actor2, actor3, actor4, actor5])

        if molarDistanceUpperActual:
            actor2 = Tests.getTextActor2D(f'Molar distance:', [40, yPos], [1, 1, 1])
            actor3 = Tests.getTextActor2D(f'{round(molarDistanceUpperActual, 2)}', [190, yPos], [1, 1, 1])
            actor4 = Tests.getTextActor2D(f' / ', [230, yPos], [1, 1, 1])
            actor5 = Tests.getTextActor2D(f'{round(molarDistanceExpected, 2)}', [250, yPos], [0, 1, 0])
            yPos -= 35
            textsActors.extend([actor1, actor2, actor3, actor4, actor5])

        if premolarDistanceLowerActual:
            actor1 = Tests.getTextActor2D(f'Lower (Pont method):', [10, yPos], [0.63, 0.7, 0], bold=True)
            yPos -= 25
            actor2 = Tests.getTextActor2D(f'Premolar distance:', [40, yPos], [1, 1, 1])
            actor3 = Tests.getTextActor2D(f'{round(premolarDistanceLowerActual, 2)}', [190, yPos], [1, 1, 1])
            actor4 = Tests.getTextActor2D(f' / ', [230, yPos], [1, 1, 1])
            actor5 = Tests.getTextActor2D(f'{round(premolarDistanceExpected, 2)}', [250, yPos], [0, 1, 0])
            yPos -= 25
            textsActors.extend([actor1, actor2, actor3, actor4, actor5])

        if molarDistanceLowerActual:
            actor2 = Tests.getTextActor2D(f'Molar distance:', [40, yPos], [1, 1, 1])
            actor3 = Tests.getTextActor2D(f'{round(molarDistanceLowerActual, 2)}', [190, yPos], [1, 1, 1])
            actor4 = Tests.getTextActor2D(f' / ', [230, yPos], [1, 1, 1])
            actor5 = Tests.getTextActor2D(f'{round(molarDistanceExpected, 2)}', [250, yPos], [0, 1, 0])
            yPos -= 25
            textsActors.extend([actor1, actor2, actor3, actor4, actor5])

        allActors: List[vtkActor] = []
        allActors.extend(jawsActor)
        allActors.extend(alignedToothActors)
        allActors.extend(textsActors)
        Utilities.DisplayActors(allActors, position=(50, 50), size=(1700, 1000))


# TODO: Fix bug in utils: line 296 - case 2836 for tests
# TODO: Bad cases: 2399, 2620, 2494
if __name__ == '__main__':
    if not Tests.initilize("2622"):
        # if not Tests.initilize("2449"):
        # if not Tests.initilize("2600"):
        # if not Tests.initilize("2416"):
        # if not Tests.initilize("2457"): # missing
        # if not Tests.initilize("2705"):
        # if not Tests.initilize("2812"):
        # if not Tests.initilize("2836"):
        # if not Tests.initilize("2085"):  # 4-th tooth bad orientation
        # if not Tests.initilize("2280"):
        # if not Tests.initilize("2287"):  #  Wrong orientation 11, 12, 14
        # if not Tests.initilize("2375"):
        # if not Tests.initilize("2399"):
        sys.exit(0)

    # Tests.CalculateAndDisplay()
    # Tests.getMissingTeethTest()
    # Tests.Visualize_Axis_Tests()

    # Tests.Calc_And_Visualize_Tooth_Lengths()

    # Tests.CalculateLengthsWithOrientedBoundingBox()
    # Tests.CutToothAlongExis_ManyPlanes()

    # Tests.Orinent_And_Calculate_Tooth_Length()

    # Tests.ProcessModels()
    # Tests.RotateToothAlongAxis()
    # Tests.OrientToothAlongAxis()
    Tests.OrientToothAlongAxis_AndDisplayFirst_8_Tooths()
