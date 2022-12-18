import vtk
from vtk.util import numpy_support

from tqdm import tqdm
import numpy as np
from typing import List, Dict, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData

from Automodeling.Utilities import Utilities


class Mesh(object):

    def __init__(self, v: np.ndarray = None, f: np.ndarray = None):
        if v is None or f is None or v.shape[0] == 0 or f.shape[0] == 0:
            self._v = None
            self._f = None
            return
        if len(v.shape) != 2 or v.shape[1] != 3:
            raise ValueError('Invalid shape of vertices array')
        if len(f.shape) != 2 or f.shape[1] != 3:
            raise ValueError('Invalid shape of faces array')
        self._v = v
        self._f = f

    @property
    def is_empty(self):
        return self._v is None or self._f is None

    @property
    def n_f(self):
        "Get number of faces"
        if self.is_empty:
            return 0
        return self._f.shape[0]

    @property
    def n_v(self):
        "Get number of vertices"
        if self.is_empty:
            return 0
        return self._v.shape[0]

    def to_vtk(self):
        "Convert to vtk.vtkPolyData"
        res = vtk.vtkPolyData()

        vtk_points = vtk.vtkPoints()
        vtk_points.SetNumberOfPoints(self.n_v)
        if self.n_v:
            for j, point in enumerate(self._v.tolist()):
                vtk_points.SetPoint(j, point)
        res.SetPoints(vtk_points)

        vtk_cells = vtk.vtkCellArray()
        if self.n_f:
            for cell in self._f.tolist():
                vtk_cells.InsertNextCell(len(cell), cell)
        res.SetPolys(vtk_cells)

        return res


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


def load_obj(f_in: str) -> Dict[str, Dict[str, Mesh]]:
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
            geometry = {
                'v': [],
                'f': [],
                'vn': [],
                'c': [],
            }
            # parse vertices and faces
            while i < len(lines) and (split_res[0] in {'v', 'f', 'vn'}):
                vec = _vector_from_obj_str_split(split_res, len(geometry['v']))
                if split_res[0] == 'v' and len(vec) == 6:
                    geometry['v'].append(vec[:3])
                    geometry['c'].append(vec[3:])
                else:
                    geometry[split_res[0]].append(vec)
                i, split_res = next(obj_split)
            data_map[groupid][objectid] = Mesh(
                np.asarray(geometry['v']),
                np.asarray(geometry['f'])
            )
            if geometry['vn']:
                data_map[groupid][objectid].v_normals = np.asarray(geometry['vn'])
            if geometry['c']:
                data_map[groupid][objectid].v_colors = np.asarray(geometry['c'])
    if i != len(lines):
        raise ValueError(f'syntax error at line {i}')
    return data_map


################################################################################################

def load_obj2(f_in: str) -> Dict[str, Dict[str, Mesh]]:
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
            geometry = {
                'v': [],
                'f': [],
                'vn': [],
                'c': [],
            }

            # parse vertices and faces
            while i < len(lines) and (split_res[0] in {'v', 'f', 'vn'}):
                vec = _vector_from_obj_str_split(split_res, len(geometry['v']))
                if split_res[0] == 'v' and len(vec) == 6:
                    geometry['v'].append(vec[:3])
                    geometry['c'].append(vec[3:])
                else:
                    geometry[split_res[0]].append(vec)
                i, split_res = next(obj_split)

            '''
            data_map[groupid][objectid] = Mesh(
                np.asarray(geometry['v']),
                np.asarray(geometry['f'])
            )
            if geometry['vn']:
                data_map[groupid][objectid].v_normals = np.asarray(geometry['vn'])
            if geometry['c']:
                data_map[groupid][objectid].v_colors = np.asarray(geometry['c'])
            '''

            V = np.asarray(geometry['v'])
            F = np.asarray(geometry['f'])

            res = vtk.vtkPolyData()
            vtk_points = vtk.vtkPoints()
            vtk_points.SetNumberOfPoints(V.shape[0])
            for j, point in enumerate(V.tolist()):
                vtk_points.SetPoint(j, point)
            res.SetPoints(vtk_points)

            vtk_cells = vtk.vtkCellArray()
            for cell in F.tolist():
                vtk_cells.InsertNextCell(len(cell), cell)
            res.SetPolys(vtk_cells)

            data_map[groupid][objectid] = res


    if i != len(lines):
        raise ValueError(f'syntax error at line {i}')
    return data_map


upper_teeth_ids = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}
lower_teeth_ids = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}

def isUpper(toothId: int) -> bool:
    return toothId in upper_teeth_ids

def isLower(toothId: int) -> bool:
    return toothId in lower_teeth_ids

def combine_meshes(mesh_seq: List[vtkPolyData], clean=False) -> vtkPolyData:
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


def test1():
    objFileName = '/home/andtokm/Projects/data/cases/2622/models/06fe_scan_crown.obj'
    with open(objFileName, 'rt') as obj_file:
        crowns = load_obj(obj_file)

    upper = crowns['upper']
    tooth = upper['u14']
    Utilities.visualize(tooth.to_vtk())


def test2():
    objFileName = '/home/andtokm/Projects/data/cases/2622/models/06fe_scan_crown.obj'
    with open(objFileName, 'rt') as obj_file:
        crowns = load_obj2(obj_file)


    upper_teeth_meshes = []
    upper = crowns['upper']
    for k, v in upper.items():
        upper_teeth_meshes.append(v)

    upper_teeth_mesh = combine_meshes(upper_teeth_meshes, False)
    Utilities.visualize(upper_teeth_mesh)

if __name__ == '__main__':
    # test1()
    test2()
