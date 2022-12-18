import numpy as np
from typing import Dict, Tuple, List
from _io import TextIOWrapper
from vtkmodules.vtkCommonCore import vtkPoints, vtkIdList
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkCellArray
from vtkmodules.vtkFiltersCore import vtkQuadricDecimation, vtkSmoothPolyDataFilter


class ToothOBJWorker(object):

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

    def write_obj_teeth(self,
                        teethDict: Dict[int, vtkPolyData],
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

                data_map[jawSide][toothId] = res

        if i != len(lines):
            raise ValueError(f'syntax error at line {i}')
        return data_map

    def decimate_poly_data(self,
                           polyData: vtkPolyData,
                           relaxation_factor=0.1,
                           out_poly_num_coefficient=0.4) -> vtkPolyData:
        num_of_polys = polyData.GetNumberOfPolys()
        out_poly_num = int(polyData.GetNumberOfCells() * out_poly_num_coefficient)
        if 0 < out_poly_num < num_of_polys:
            decimator: vtkQuadricDecimation = vtkQuadricDecimation()
            decimator.SetInputData(polyData)
            decimator.SetTargetReduction(float(num_of_polys - out_poly_num) / num_of_polys)
            decimator.Update()
            smoothFilter: vtkSmoothPolyDataFilter = vtkSmoothPolyDataFilter()
            smoothFilter.SetInputConnection(decimator.GetOutputPort())
            smoothFilter.SetNumberOfIterations(1)
            smoothFilter.SetRelaxationFactor(relaxation_factor)
            smoothFilter.Update()
            polyData = smoothFilter.GetOutput()

        return polyData

    def desimateTeethObj(self,
                         outPath: str):
        teeth: Dict[int, vtkPolyData] = {k: self.decimate_poly_data(v) for k, v in self.teethMap.items()}
        self.write_obj_teeth(teeth, outPath)
