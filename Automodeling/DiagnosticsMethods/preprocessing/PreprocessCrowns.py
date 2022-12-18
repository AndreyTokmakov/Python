import vtk
import numpy as np
from typing import List, Dict, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData

def is_not_empty(line: str) -> bool:
    # Return True if we don't skip this line of obj file, False otherwise
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
        jawSide = ' '.join(split_res[1:]) # upper/lower
        data_map[jawSide] = {}
        i, split_res = next(obj_split)
        # parse objects
        while i < len(lines) and split_res[0] == 'o':
            toothId = int((' '.join(split_res[1:]))[1:])
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

            data_map[jawSide][toothId] = res

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


def transformPolyData(polyData: vtkPolyData) -> vtkPolyData:
    transform: vtk.vtkTransform = vtk.vtkTransform()
    transform.RotateX(90)
    transform.RotateY(180)

    transformFilter: vtk.vtkTransformPolyDataFilter = vtk.vtkTransformPolyDataFilter()
    transformFilter.SetInputData(polyData)
    transformFilter.SetTransform(transform)
    transformFilter.Update()
    return transformFilter.GetOutput()


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
def PreprocessCrowns():
    objFileName = '/home/andtokm/Projects/data/cases/2622/models/06fe_scan_crown.obj'
    dstFileName = '/home/andtokm/Projects/data/cases/2622/automodeling2/out/2622_teeth.obj'

    with open(objFileName, 'rt') as obj_file:
        crowns = readTeethOBJ(obj_file)

    teethMap: Dict[str, vtkPolyData] = dict()
    for _, teeth_dict in crowns.items():
        for toothId, polyData in teeth_dict.items():
            data = transformPolyData(polyData)
            teethMap[toothId] = decimatePolyData(data)

    writeTeethOBJ(teethMap, dstFileName)


if __name__ == '__main__':
    PreprocessCrowns()
