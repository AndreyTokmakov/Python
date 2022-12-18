from typing import Dict

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

from VTK_Experiments.Types import Point2D, Point3D, Line3D
from VTK_Experiments.Utilities import Utilities


def read_obj_teeth(mesh_path: str) -> Dict[int, vtk.vtkPolyData]:
    data_map = {}
    with open(mesh_path, 'rt') as infile:
        lines = infile.readlines()
        n = 0;
        i = 0
        while i < len(lines) and 'g' == lines[i].split()[0]:
            i += 1
            n += 1;
            while i < len(lines) and 'o' == lines[i].split()[0]:
                objectpid = int(lines[i].split()[1][1:])
                data_map[objectpid] = vtk.vtkPolyData()
                points = []
                i += 1
                while i < len(lines) and 'v' == lines[i].split()[0]:
                    pts = [float(s) for s in lines[i][2:].split()]
                    points.append(pts)
                    i += 1

                vtk_points = vtk.vtkPoints()
                # vtk_points.SetNumberOfPoints(len(points))
                for j, point in enumerate(points):
                    vtk_points.InsertNextPoint(point)

                data_map[objectpid].SetPoints(vtk_points)
                cells = []
                while i < len(lines) and 'f' == lines[i].split()[0]:
                    cell = [int(s) + len(points) if int(s) < 0 else int(s) for s in lines[i][2:].split()];
                    cells.append(cell)
                    i += 1

                vtk_cells = vtk.vtkCellArray()
                for j in range(len(cells)):
                    vtk_cells.InsertNextCell(3, cells[j])
                data_map[objectpid].SetPolys(vtk_cells)

    return data_map


class ReadersTests:
    STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'

    def read_stl_test(self):
        data: vtkPolyData = Utilities.readStl(self.STL_FILE)
        Utilities.visualize(data)


class PointsTests:

    def Test(self):
        pts = [Point3D(1, 2, 0), Point3D(2, 3, 0), Point3D(3, 4, 0)]
        actor: vtkActor = Utilities.getPointsActor(pts)
        Utilities.DisplayActors([actor])


class LinesTests:

    def Test(self):
        actor: vtkActor = Utilities.getLineActor(Line3D(Point3D(1, 1, 1), Point3D(5, 5, 5)))
        Utilities.DisplayActors([actor])

    def AngleBetweenLines(self):
        actor1: vtkActor = Utilities.getLineActor(Line3D(Point3D(1, 1, 1), Point3D(5, 51, 5)))
        actor2: vtkActor = Utilities.getLineActor(Line3D(Point3D(-2, -2, -2), Point3D(41, 5, 7)))
        Utilities.DisplayActors([actor1, actor2])


def Test():
    id_mesh_dict = read_obj_teeth("/home/andtokm/Projects/data/cases/2878/automodeling/out/2878_teeth.obj")
    id_mesh_dict = {key: {'mesh': value} for key, value in id_mesh_dict.items()
                    if not (key in [18, 28, 38, 48])}

    mesh: vtkPolyData = id_mesh_dict.get(21)['mesh']
    print(type(mesh))

    Utilities.visualize(mesh)


if __name__ == '__main__':
    readersTests = ReadersTests()
    # readersTests.read_stl_test()

    # PointsTests().Test()

    # LinesTests().Test()
    LinesTests().AngleBetweenLines()

    # Test()