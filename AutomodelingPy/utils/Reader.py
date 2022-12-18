import numpy as np
from typing import Dict, Tuple, List
from vtkmodules.vtkCommonCore import vtkPoints, vtkIdList
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkCellArray
from vtkmodules.vtkFiltersCore import vtkQuadricDecimation, vtkSmoothPolyDataFilter


# The class is intended for parsing/preprocessing crown data in the format .obj
# 1. Reads data from a file or from a string
# 2. Parses the file line by line and saves the data as vtkPolyData
class Reader(object):

    def __init__(self):
        self.teethMap: Dict[int, vtkPolyData] = {}

    def init_from_data(self, crowns_data: str) -> None:
        """
        Accepts and parses data as a string
        (the byte stream does not decode - there will be an error)
        :param crowns_data: crowns file as Strings
        :return: None
        :except: may throw
        """
        lines = crowns_data.splitlines()
        self.parse_crowns_data_lines(lines)

    def init_from_file(self, obj_file) -> None:
        """
        Parses .obj file to Dict[ToothID, vtkPolyData]
        Note: It is required pass only the paths of local files - the URL format is not supported
        :param obj_file: local path to .obj file
        :return: None
        :except: may throw
        """
        with open(obj_file, 'rt') as obj_file:
            lines = obj_file.readlines()
        self.parse_crowns_data_lines(lines)

    @staticmethod
    def is_not_empty(line: str) -> bool:
        # Return True if we don't skip this line of obj file, False otherwise
        return not (line.strip() == '' or line[0] == '#' or line[:2] in {
            'vt', 'vp'} or line[:6] in {'mtllib', 'usemtl'})

    @staticmethod
    def __split_lines(lines: Tuple[str]) -> Tuple[int, List[str]]:
        """
        Generator for index and splitted lines. Also visualize progress using tqdm.
        :param lines: lines of obj file
        :return: generator of index and splitted line
        """
        for i in range(len(lines)):
            yield i, lines[i].split()
        yield len(lines), []

    @staticmethod
    def _vector_from_obj_str_split(split: List[str],
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

    @staticmethod
    def write_obj_teeth(teethDict: Dict[int, vtkPolyData],
                        out_path: str) -> None:
        with open(out_path, 'wt') as outfile:
            for jaw_type in ('lower', 'upper'):
                outfile.write('g {}\n'.format(jaw_type))
                for key, mesh in teethDict.items():
                    if 'lower' == jaw_type and key // 10 in (1, 2) or 'upper' == jaw_type and key // 10 in (3, 4):
                        continue
                    outfile.write('o {}{}\n'.format(jaw_type[0], key))
                    points_num = mesh.GetNumberOfPoints()
                    polys_num = mesh.GetNumberOfCells()
                    for i in range(points_num):
                        point = mesh.GetPoint(i)
                        outfile.write(' '.join(['v', str(point[0]), str(point[1]), str(point[2])]) + '\n')
                    for i in range(polys_num):
                        id_list = vtkIdList()
                        mesh.GetCellPoints(i, id_list)
                        outfile.write(' '.join(['f',
                                                str(id_list.GetId(0) - points_num),
                                                str(id_list.GetId(1) - points_num),
                                                str(id_list.GetId(2) - points_num)]) + '\n')

    def parse_crowns_data_lines(self, lines: List[str]) -> None:
        lines = tuple(filter(Reader.is_not_empty, lines))
        if lines is None:
            raise ValueError(f'Empty file')
        obj_split = Reader.__split_lines(lines)

        i, split_res = next(obj_split)
        while i < len(lines) and split_res[0] == 'g':
            i, split_res = next(obj_split)
            # parse objects
            while i < len(lines) and split_res[0] == 'o':
                toothId = int((' '.join(split_res[1:]))[1:])
                i, split_res = next(obj_split)
                geometry = {'v': [], 'f': [], 'vn': [], 'c': []}

                # parse vertices and faces
                while i < len(lines) and (split_res[0] in {'v', 'f', 'vn'}):
                    vec = Reader._vector_from_obj_str_split(split_res, len(geometry['v']))
                    if split_res[0] == 'v' and len(vec) == 6:
                        geometry['v'].append(vec[:3])
                        geometry['c'].append(vec[3:])
                    else:
                        geometry[split_res[0]].append(vec)
                    i, split_res = next(obj_split)

                pointsArray = np.asarray(geometry['v'])
                res = vtkPolyData()
                vtk_points = vtkPoints()
                vtk_points.SetNumberOfPoints(pointsArray.shape[0])
                for j, point in enumerate(pointsArray.tolist()):
                    vtk_points.SetPoint(j, point)
                res.SetPoints(vtk_points)

                cellsArray = np.asarray(geometry['f'])
                vtk_cells = vtkCellArray()
                for cell in cellsArray.tolist():
                    vtk_cells.InsertNextCell(len(cell), cell)
                res.SetPolys(vtk_cells)
                self.teethMap[toothId] = res

        if i != len(lines):
            raise ValueError(f'Syntax error at line {i}')

    @staticmethod
    def decimate_poly_data(polyData: vtkPolyData,
                           relaxation_factor=0.1,
                           out_poly_num_coefficient=0.4) -> vtkPolyData:
        num_of_polys = polyData.GetNumberOfPolys()
        out_poly_num = int(polyData.GetNumberOfCells() * out_poly_num_coefficient)
        if 0 < out_poly_num < num_of_polys:
            decimation: vtkQuadricDecimation = vtkQuadricDecimation()
            decimation.SetInputData(polyData)
            decimation.SetTargetReduction(float(num_of_polys - out_poly_num) / num_of_polys)
            decimation.Update()

            smoothFilter: vtkSmoothPolyDataFilter = vtkSmoothPolyDataFilter()
            smoothFilter.SetInputConnection(decimation.GetOutputPort())
            smoothFilter.SetNumberOfIterations(1)
            smoothFilter.SetRelaxationFactor(relaxation_factor)
            smoothFilter.Update()

            polyData = smoothFilter.GetOutput()

        return polyData

    def decimate_teeth_obj(self,
                           outPath: str):
        teeth: Dict[int, vtkPolyData] = {k: Reader.decimate_poly_data(v) for k, v in self.teethMap.items()}
        Reader.write_obj_teeth(teeth, outPath)
