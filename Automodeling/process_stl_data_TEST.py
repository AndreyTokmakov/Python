

import logging
import vtk

from typing import Dict, List
from pathlib import Path
from inspect import currentframe, getframeinfo
from optparse import OptionParser
from os.path import isabs, normpath
from typing import Dict
from teeth_movement.classification import classify_teeth
from teeth_movement.mesh_io import read_obj, read_stl, write_obj_teeth, write_stl
from teeth_movement.utils import preprocess_mesh

# import tmov

STL_LOWER_CROWNS_597 = "/home/andtokm/Projects/teeth_movement/example/data/P-497_-_lower_-_01_-_Model.stl"
STL_UPPER_CROWNS_597 = "/home/andtokm/Projects/teeth_movement/example/data/P-497_-_upper_-_01_-_Model.stl"

STL_LOWER_CROWNS_12805 = "/home/andtokm/Projects/data/out/12805/12805_lower.stl"
STL_UPPER_CROWNS_12805 = "/home/andtokm/Projects/data/out/12805/12805_upper.stl"

STL_LOWER_CROWNS_13078 = "/home/andtokm/Projects/data/out/13078/13078_lower.stl"
STL_UPPER_CROWNS_13078 = "/home/andtokm/Projects/data/out/13078/13078_upper.stl"

STL_LOWER_CROWNS_13181 = "/home/andtokm/Projects/data/out/13181/13181_lower.stl"
STL_UPPER_CROWNS_13181 = "/home/andtokm/Projects/data/out/13181/13181_upper.stl"

STL_LOWER_CROWNS_6821 = "/home/andtokm/Projects/data/cases/6821/automodeling/crowns/6821_lower.stl"
STL_UPPER_CROWNS_6821 = "/home/andtokm/Projects/data/cases/6821/automodeling/crowns/6821_upper.stl"


CONST_STL_OUTPUT = "/home/andtokm/Projects/data/out/"

'''
CONST_OBJ_FILENAME_OUT_597 = CONST_STL_OUTPUT + "497_teeth.obj"
CONST_OBJ_FILENAME_OUT_12805 = CONST_STL_OUTPUT + "12805_teeth.obj"
CONST_OBJ_FILENAME_OUT_13078 = CONST_STL_OUTPUT + "13078_teeth.obj"
CONST_OBJ_FILENAME_OUT_13078 = CONST_STL_OUTPUT + "13078_teeth.obj"
'''

RELAXATION_FACTOR = 0.1 # 0.01  
OUT_POLY_COEF = 0.8
ITER_NUM = 2 # 2 org #4 incr if bad symmetry_axis
OUT_POLY_NUM = 60000


def separate_connected_components(mesh: vtk.vtkPolyData) -> List[vtk.vtkPolyData]:
    teethsList = []
    connectivityFilter = vtk.vtkPolyDataConnectivityFilter()
    connectivityFilter.SetInputData(mesh)
    connectivityFilter.Update()
    regionsNum = connectivityFilter.GetNumberOfExtractedRegions()
    print(f"regionsNum = {regionsNum}")
    for regionId in range(regionsNum):
        connectivityFilter = vtk.vtkPolyDataConnectivityFilter()
        connectivityFilter.SetInputData(mesh)
        connectivityFilter.SetExtractionModeToSpecifiedRegions()
        connectivityFilter.AddSpecifiedRegion(regionId)

        connectivityFilter.ScalarConnectivityOn()
        connectivityFilter.FullScalarConnectivityOn()

        connectivityFilter.Update()
        clean_poly_data = vtk.vtkCleanPolyData()
        clean_poly_data.SetInputData(connectivityFilter.GetOutput())
        clean_poly_data.Update()
        teethsList.append(clean_poly_data.GetOutput())
    return teethsList


def preprocess_mesh(mesh: vtk.vtkPolyData,
                    iter_num=1,
                    relaxation_factor=0.01,
                    decimation=True,
                    out_poly_num_coefficient=0.8,
                    poly_num=None
                    ) -> vtk.vtkPolyData:
    """Smooth mesh

    Smooth mesh using VTK tools

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param logging: Log
    :type logging: logging
    :param iter_num: Number of smoothing iterations
    :type iter_num: int
    :param relaxation_factor: Relaxation factor as float
    :type relaxation_factor: float
    :param decimation: decimation apply
    :type decimation: boolean
    :param out_poly_num_coefficient: decimation coefficient if need poly_num options
    :type out_poly_num_coefficient: float
    :param poly_num: decimation polys or None or 0 (use out_poly_num_coefficient)
    :type poly_num: int
    :returns: Smoothed mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """

    # OUT_POLY_NUM=60000 for old code preprocessing + RELAXATION_FACTOR=0.1
    # RELAXATION_FACTOR=0.1 or 0.01 for preprocessing

    if iter_num and iter_num > 0:
        print(f'smooth iter_num={iter_num}, relaxation_factor={relaxation_factor}')
        smooth_filter = vtk.vtkSmoothPolyDataFilter()
        smooth_filter.SetInputData(mesh)
        smooth_filter.SetNumberOfIterations(iter_num)
        smooth_filter.SetRelaxationFactor(relaxation_factor)
        smooth_filter.Update()
        mesh = smooth_filter.GetOutput()

    if decimation:
        num_of_polys = mesh.GetNumberOfPolys()
        out_poly_num = 0
        if not poly_num or poly_num <= 0:
            out_poly_num = int(mesh.GetNumberOfCells() * out_poly_num_coefficient)
            print(f'decimate {num_of_polys} to {out_poly_num} opt: coef={out_poly_num_coefficient}')
        else:
            out_poly_num = poly_num
            print(f'decimate {num_of_polys} to {out_poly_num}')

        if out_poly_num > 0 and num_of_polys > out_poly_num:
            decimate = vtk.vtkQuadricDecimation()
            decimate.SetInputData(mesh)
            decimate.SetTargetReduction(float(num_of_polys - out_poly_num) / num_of_polys)
            decimate.Update()
            iter = 1
            if iter_num and iter_num > 0:
                iter = iter_num
            smooth_filter = vtk.vtkSmoothPolyDataFilter()
            smooth_filter.SetInputConnection(decimate.GetOutputPort())
            smooth_filter.SetNumberOfIterations(iter)
            smooth_filter.SetRelaxationFactor(relaxation_factor)
            smooth_filter.Update()
            mesh = smooth_filter.GetOutput()
    return mesh


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('AutoModeling')

    lowerTeethMesh: vtk.vtkPolyData = read_stl(STL_LOWER_CROWNS_6821)
    # upperTeethMesh: vtk.vtkPolyData = read_stl(STL_UPPER_CROWNS_13078)
   
    # missingiIds = [38, 48]  # Missing upper wisdom teeths fpr 497
    # missingiIds = [18, 28]  # Missing upper wisdom teeths fpr 12805

    lowerTeethMesh = preprocess_mesh(lowerTeethMesh)
    lowerTeethsSparatedMesh: list = separate_connected_components(lowerTeethMesh)
    print(f"Lower teeths count {len(lowerTeethsSparatedMesh)}")

    # upperTeethsSparatedMesh: list = separate_connected_components(upperTeethMesh)
    # print(f"Upper teeths count {len(upperTeethsSparatedMesh)}")

    counter = 1
    for data in lowerTeethsSparatedMesh:
        path = CONST_STL_OUTPUT + "Lower_"+ str(counter) + "_tooth.stl"
        # write_stl(data, path)
        # counter += 1

    # print(counter)


    # Cassify
    '''
    teethsMap: Dict[int, vtk.vtkPolyData] = classify_teeth(
                separate_connected_components(lowerTeethMesh),
                separate_connected_components(upperTeethMesh),
                missingiIds)
    '''

    # Write
    # write_obj_teeth(teethsMap, CONST_OBJ_FILENAME_OUT_597)

    '''
    upperToothIds = (11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28)
    lowerToothIds = (41, 42, 43, 44, 45, 46, 47, 48, 31, 32, 33, 34, 35, 36, 37, 38)
    for k, v in teethsMap.items():
        if k in lowerToothIds:
            path = CONST_STL_OUTPUT + "Lower_"+ str(k) + "_tooth.stl"
            write_stl(v, path)
        if k in upperToothIds:
            path = CONST_STL_OUTPUT + "Upper_"+ str(k) + "_tooth.stl"
            write_stl(v, path)
    '''