from typing import Dict
import vtk

def read_obj(mesh_path: str) -> vtk.vtkPolyData:
    """Read OBJ

    Reads OBJ mesh from disk
    :param mesh_path: Path to pbj mesh
    :type mesh_path: str
    :returns: Mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """
    obj_reader = vtk.vtkOBJReader()
    obj_reader.SetFileName(mesh_path)
    obj_reader.Update()
    return obj_reader.GetOutput()


def read_stl(mesh_path: str) -> vtk.vtkPolyData:
    """Read STL

    Reads STL mesh from disk

    :param mesh_path: Path to stl mesh
    :type mesh_path: str
    :returns: Mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """
    obj_reader = vtk.vtkSTLReader()
    obj_reader.SetFileName(mesh_path)
    obj_reader.Update()
    return obj_reader.GetOutput()


def read_obj_teeth(mesh_path: str) -> Dict[int, vtk.vtkPolyData]:
    """Read OBJ teeth

    Read teeth object to returs a dictionary with individual teeth

    :param mesh_path: Path to obj mesh
    :type mesh_path: str
    :returns: Disctionary with teeth objects as VTK objects
    :rtype: {Dict[int, vtk.vtkPolyData]}
    """
    data_map = {}
    with open(mesh_path, 'rt') as infile:
        lines = infile.readlines()
        i = 0
        while i < len(lines) and 'g' == lines[i].split()[0]:
            jaw_type = lines[i].split()[1]
            i += 1
            while i < len(lines) and 'o' == lines[i].split()[0]:
                objectpid = int(lines[i].split()[1][1:])
                data_map[objectpid] = vtk.vtkPolyData()
                points = []
                i += 1
                while i < len(lines) and 'v' == lines[i].split()[0]:
                    points.append([float(s) for s in lines[i][2:].split()])
                    i += 1
                vtk_points = vtk.vtkPoints()
                vtk_points.SetNumberOfPoints(len(points))
                for j, point in enumerate(points):
                    vtk_points.SetPoint(j, point)
                data_map[objectpid].SetPoints(vtk_points)
                cells = []
                while i < len(lines) and 'f' == lines[i].split()[0]:
                    cells.append([int(s) + len(points) if int(s) < 0 else int(s)\
                        for s in lines[i][2:].split()])
                    i += 1
                vtk_cells = vtk.vtkCellArray()
                for j in range(len(cells)):
                    vtk_cells.InsertNextCell(3, cells[j])
                data_map[objectpid].SetPolys(vtk_cells)
    return data_map


def write_stl(mesh: vtk.vtkPolyData, mesh_path: str):
    """Write STL mesh

    Writes STL mesh from VTK mesh object
    :param mesh: VTK object
    :type mesh: vtk.vtkPolyData
    :param mesh_path: Path to save STL file
    :type mesh_path: str
    """
    stl_writer = vtk.vtkSTLWriter()
    stl_writer.SetInputData(mesh)
    stl_writer.SetFileName(mesh_path)
    stl_writer.Write()


def write_obj(mesh: vtk.vtkPolyData, mesh_path: str):
    """Write OBJ mesh

    Writes OBJ mesh from VTK mesh object
    :param mesh: VTK object
    :type mesh: vtk.vtkPolyData
    :param mesh_path: Path to save OBJ file
    :type mesh_path: str
    """
    with open(mesh_path, 'wt') as outfile:
        for i in range(mesh.GetNumberOfPoints()):
            point = mesh.GetPoint(i)
            outfile.write(' '.join([
                    'v',
                    str(point[0]),
                    str(point[1]),
                    str(point[2])]) + '\n')
        for i in range(mesh.GetNumberOfCells()):
            id_list = vtk.vtkIdList()
            mesh.GetCellPoints(i, id_list)
            outfile.write(' '.join([
                    'f',
                    str(id_list.GetId(0) + 1),
                    str(id_list.GetId(1) + 1),
                    str(id_list.GetId(2) + 1)]) + '\n')


def write_obj_teeth(
        teeth_map: Dict[int, vtk.vtkPolyData],
        out_path: str) -> None:
    """Write teeth objects

    Writes obj file with classified crown models

    :param teeth_map: Dictionary with classified teeth objects as VTK objects
    :type teeth_map: Dict[int, vtk.vtkPolyData]
    :param out_path: Save path
    :type out_path: str
    """
    with open(out_path, 'wt') as outfile:
        for jaw_type in ('lower', 'upper'):
            outfile.write('g {}\n'.format(jaw_type))
            for key, mesh in teeth_map.items():
                if 'lower' == jaw_type and key // 10 in (1, 2) or\
                        'upper' == jaw_type and key // 10 in (3, 4):
                    continue
                print(key)
                outfile.write('o {}{}\n'.format(jaw_type[0], key))
                points_num = mesh.GetNumberOfPoints()
                polys_num = mesh.GetNumberOfCells()
                for i in range(points_num):
                    point = mesh.GetPoint(i)
                    outfile.write(' '.join([
                        'v',
                        str(point[0]),
                        str(point[1]),
                        str(point[2])]) + '\n'
                    )
                for i in range(polys_num):
                    id_list = vtk.vtkIdList()
                    mesh.GetCellPoints(i, id_list)
                    outfile.write(' '.join([
                        'f',
                        str(id_list.GetId(0) - points_num),
                        str(id_list.GetId(1) - points_num),
                        str(id_list.GetId(2) - points_num)]) + '\n'
                    )
