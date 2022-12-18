from pathlib import Path

import vtk
import numpy as np
from typing import List, Dict, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData
from Automodeling.Utilities import Utilities


def is_not_empty(line: str) -> bool:
    """
    Return True if we don\'t skip this line of obj file, False otherwise
    """
    return not (line.strip() == '' or line[0] == '#' or line[:2] in {
        'vt', 'vp'} or line[:6] in {'mtllib', 'usemtl'})


def get_obj_split(lines: List[str]) -> Tuple[int, List[str]]:
    """
    Generator for index and splitted lines. Also visualize progress using tqdm.
    :param lines: lines of obj file
    :return: generator of index and splitted line
    """
    for i in range(len(lines)):
        yield i, lines[i].split()
    yield len(lines), []


def _vector_from_obj_str_split(split: List[str], v_num: int) -> List[float]:
    if split[0] == 'v':
        return [float(s) for s in split[1:]]
    if split[0] == 'f':
        polygon = []
        for s in split[1:4]:
            s_split = s.split('/')
            v_idx = ''
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


def readTeethOBJ(f_in: str) -> Dict[str, Dict[str, vtkPolyData]]:
    data_map = {}
    lines = f_in.readlines()
    lines = tuple(filter(is_not_empty, lines))
    if not lines:
        raise ValueError(f'Empty file')
    obj_split = get_obj_split(lines)

    # parse groups
    i, split_res = next(obj_split)
    while i < len(lines) and split_res[0] == 'g':
        groupid = ' '.join(split_res[1:])
        data_map[groupid] = {}
        i, split_res = next(obj_split)
        # parse objects
        while i < len(lines) and split_res[0] == 'o':
            objectid = ' '.join(split_res[1:])
            i, split_res = next(obj_split)
            geometry = {'v': [], 'f': [], 'vn': [], 'c': []}

            # parse vertices and faces
            while i < len(lines) and (split_res[0] in {'v', 'f', 'vn'}):
                vec = _vector_from_obj_str_split(split_res, len(geometry['v']))
                if split_res[0] == 'v' and len(vec) == 6:
                    geometry['v'].append(vec[:3])
                    geometry['c'].append(vec[3:])
                else:
                    geometry[split_res[0]].append(vec)
                i, split_res = next(obj_split)

            pointsArray = np.asarray(geometry['v'])
            cellsArray = np.asarray(geometry['f'])

            res = vtk.vtkPolyData()
            vtk_points = vtk.vtkPoints()
            vtk_points.SetNumberOfPoints(pointsArray.shape[0])
            for j, point in enumerate(pointsArray.tolist()):
                vtk_points.SetPoint(j, point)
            res.SetPoints(vtk_points)

            vtk_cells = vtk.vtkCellArray()
            for cell in cellsArray.tolist():
                vtk_cells.InsertNextCell(len(cell), cell)
            res.SetPolys(vtk_cells)

            data_map[groupid][objectid] = res

    if i != len(lines):
        raise ValueError(f'syntax error at line {i}')
    return data_map


def writeTeethOBJ(teeth_map: Dict[int, vtk.vtkPolyData],
                  out_path: str) -> None:
    with open(out_path, 'wt') as outfile:
        for jaw_type in ('lower', 'upper'):
            outfile.write('g {}\n'.format(jaw_type))
            for key, mesh in teeth_map.items():
                if 'lower' == jaw_type and key // 10 in (1, 2) or 'upper' == jaw_type and key // 10 in (3, 4):
                    continue
                outfile.write('o {}{}\n'.format(jaw_type[0], key))
                points_num = mesh.GetNumberOfPoints()
                for i in range(points_num):
                    point = mesh.GetPoint(i)
                    outfile.write(' '.join(['v',
                                            str(point[0]),
                                            str(point[1]),
                                            str(point[2])]) + '\n')
                polys_num = mesh.GetNumberOfCells()
                for i in range(polys_num):
                    id_list = vtk.vtkIdList()
                    mesh.GetCellPoints(i, id_list)
                    outfile.write(' '.join(['f',
                                            str(id_list.GetId(0) - points_num),
                                            str(id_list.GetId(1) - points_num),
                                            str(id_list.GetId(2) - points_num)]) + '\n')


'''

# TODO: Error parsing file '/home/andtokm/Projects/data/cases/2622/models/06fe_scan_crown.obj'
# TOOD: Fix it, Check perf

def read_obj_teeth(mesh_path: str) -> Dict[int, vtk.vtkPolyData]:
    data_map = {}
    with open(mesh_path, 'rt') as infile:
        lines = infile.readlines()

        n = 0; i = 0
        while i < len(lines) and 'g' == lines[i].split()[0]:
            # jaw_type = lines[i].split()[1]
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
                vtk_points.SetNumberOfPoints(len(points))
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



upper_teeth_ids = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}
lower_teeth_ids = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}

def isUpper(toothId: int) -> bool:
    return toothId in upper_teeth_ids

def isLower(toothId: int) -> bool:
    return toothId in lower_teeth_ids
    
'''


def appendPolyData(mesh_seq: List[vtkPolyData], clean=False) -> vtkPolyData:
    append_filter = vtk.vtkAppendPolyData()
    for mesh in mesh_seq:
        append_filter.AddInputData(mesh)
    append_filter.Update()
    result = append_filter.GetOutput()
    if clean:
        clean_filter = vtk.vtkCleanPolyData()
        clean_filter.SetInputData(result)
        clean_filter.Update()
        result = clean_filter.GetOutput()
    return result


def transformPolyData(polyData: vtkPolyData) -> vtkPolyData:
    transform: vtk.vtkTransform = vtk.vtkTransform()
    transform.RotateX(90)
    transform.RotateY(180)

    transformFilter: vtk.vtkTransformPolyDataFilter = vtk.vtkTransformPolyDataFilter()
    transformFilter.SetInputData(polyData)
    transformFilter.SetTransform(transform)
    transformFilter.Update()
    return transformFilter.GetOutput()


def writeStl(polyData: vtkPolyData, path: str) -> None:
    stl_writer = vtk.vtkSTLWriter()
    stl_writer.SetFileName(path)
    stl_writer.SetInputData(polyData)
    stl_writer.SetFileTypeToBinary()
    stl_writer.Write()


def writeObj(polyData: vtkPolyData, path: str) -> None:
    stl_writer = vtk.vtkOBJWriter()
    stl_writer.SetFileName(path)
    stl_writer.SetInputData(polyData)
    # stl_writer.SetFileTypeToBinary()
    stl_writer.Write()


def Convert_OBJ_2_STL_ForAutomodeling():
    objFileName = '/home/andtokm/Projects/data/cases/2622/models/06fe_scan_crown.obj'
    with open(objFileName, 'rt') as obj_file:
        crowns = readTeethOBJ(obj_file)

    upper_teeth_data = []
    lower_teeth_data = []
    for k, v in crowns['upper'].items():
        upper_teeth_data.append(v)
    for k, v in crowns['lower'].items():
        lower_teeth_data.append(v)

    upper_teeth_mesh = appendPolyData(upper_teeth_data, False)
    lower_teeth_mesh = appendPolyData(lower_teeth_data, False)

    upper_teeth_mesh = transformPolyData(upper_teeth_mesh)
    lower_teeth_mesh = transformPolyData(lower_teeth_mesh)

    # Utilities.visualize(upper_teeth_mesh)
    # Utilities.visualize(lower_teeth_mesh)

    writeStl(lower_teeth_mesh, "/home/andtokm/Projects/data/cases/2622/automodeling2/crowns/lower.stl")
    writeStl(upper_teeth_mesh, "/home/andtokm/Projects/data/cases/2622/automodeling2/crowns/upper.stl")


def decimatePolyData(polyData: vtk.vtkPolyData,
                     relaxation_factor=0.1,
                     out_poly_num_coefficient=0.4
                     ) -> vtk.vtkPolyData:
    num_of_polys = polyData.GetNumberOfPolys()
    out_poly_num = int(polyData.GetNumberOfCells() * out_poly_num_coefficient)
    if 0 < out_poly_num < num_of_polys:
        decimator: vtk.vtkQuadricDecimation = vtk.vtkQuadricDecimation()
        decimator.SetInputData(polyData)
        decimator.SetTargetReduction(float(num_of_polys - out_poly_num) / num_of_polys)
        decimator.Update()
        smoothFilter: vtk.vtkSmoothPolyDataFilter = vtk.vtkSmoothPolyDataFilter()
        smoothFilter.SetInputConnection(decimator.GetOutputPort())
        smoothFilter.SetNumberOfIterations(1)
        smoothFilter.SetRelaxationFactor(relaxation_factor)
        smoothFilter.Update()
        polyData = smoothFilter.GetOutput()
    return polyData


# Reads original OBJ file (*_scan_crown.obj) into Dict[str, vtkPolyData], then:
# 1. Process each tooth with decimatePolyData()
# 2. Write Dict to the .obj file manually
# TODO: Fix and refactor decimatePolyData()
# TODO: Measure method performance (use Threads???)
def Convert_OBJ_2_OBJ_ForAutomodeling():
    objFileName = '/home/andtokm/Projects/data/cases/2622/models/06fe_scan_crown.obj'
    dstFileName = '/home/andtokm/Projects/data/cases/2622/automodeling2/out/2622_teeth.obj'

    with open(objFileName, 'rt') as obj_file:
        crowns = readTeethOBJ(obj_file)

    teethMap: Dict[str, vtkPolyData] = dict()
    for _, teeth_dict in crowns.items():
        for tooth_id, polyData in teeth_dict.items():
            data = transformPolyData(polyData)
            teethMap[int(tooth_id[1:])] = decimatePolyData(data)

    writeTeethOBJ(teethMap, dstFileName)


if __name__ == '__main__':
    # Convert_OBJ_2_STL_ForAutomodeling()
    Convert_OBJ_2_OBJ_ForAutomodeling()
