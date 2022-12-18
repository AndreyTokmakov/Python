
import logging

from teeth_movement.utils import get_centroid, list_diff
from typing import Dict, List
from pathlib import Path
from inspect import currentframe, getframeinfo
from optparse import OptionParser
from os.path import isabs, normpath
from typing import Dict
from teeth_movement.classification import classify_teeth
from teeth_movement.mesh_io import read_obj, read_stl, write_obj_teeth, write_stl
from teeth_movement.utils import separate_connected_components, preprocess_mesh

import vtk
import numpy
# import tmov

CONST_OBJ_FILENAME_OUT_12805 = "/home/andtokm/Projects/teeth_movement/example/out/12805/12805_teeth.obj"
CONST_OBJ_FILENAME_12805 = "/home/andtokm/Projects/data/cases/12805/models/b82b_scan_crown.obj"

CONST_OBJ_FILENAME_OUT_13078 = "/home/andtokm/Projects/teeth_movement/example/out/13078/13078_teeth.obj"
CONST_OBJ_FILENAME_13078 = "/home/andtokm/Projects/data/cases/13078/models/7dc7_scan_crown.obj"

CONST_STL_OUTPUT = "/home/andtokm/Projects/data/out/"

RELAXATION_FACTOR = 0.1 # 0.01  
OUT_POLY_COEF = 0.8
ITER_NUM = 2 # 2 org #4 incr if bad symmetry_axis
OUT_POLY_NUM = 60000


def classify(lowerTeethsMeshes: List[vtk.vtkPolyData],
             upperTeeth_Meshes: List[vtk.vtkPolyData],
             missingTeeths: List[int]) -> Dict[int, vtk.vtkPolyData]:

    # TODO: Move to const
    upperToothIds = (11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28)
    lowerToothIds = (41, 42, 43, 44, 45, 46, 47, 48, 31, 32, 33, 34, 35, 36, 37, 38)

    centroidsLower = numpy.zeros((len(lowerTeethsMeshes), 4))
    centroidsUpper = numpy.zeros((len(upperTeeth_Meshes), 4))

    for i, tooth_model in enumerate(lowerTeethsMeshes):
        centroidsLower[i, :3] = get_centroid(tooth_model)
        centroidsLower[i, 3] = i
        print(f"Lower: {centroidsLower[i]}")

    for i, tooth_model in enumerate(upperTeeth_Meshes):
        centroidsUpper[i, :3] = get_centroid(tooth_model)
        centroidsUpper[i, 3] = i
        print(f"Upper: {centroidsUpper[i]}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('AutoModeling')
    # log.info(f'Flename : {CONST_OBJ_FILENAME_12805}')

    teethMesh: vtk.vtkPolyData = read_obj(CONST_OBJ_FILENAME_12805)

    # Process mesh:
    # teethMesh = preprocess_mesh(teethMesh, log, ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)

    teethMeshSeparated: List = separate_connected_components(teethMesh)

    # Separate to upper and lower 
    upperTeethMesh = teethMeshSeparated[0:14]
    lowerTeethMesh = teethMeshSeparated[14:]

    # Missing upper wisdom teeths fpr 12805
    missingiIds = [18, 28]

    # Missing upper wisdom teeths fpr 13078
    # missingiIds = [18, 28, 38, 48]

    # Classify
    #teethsMap: Dict[int, vtk.vtkPolyData] = classify_teeth(lowerTeethMesh, upperTeethMesh, missingiIds)
    teethsMap: Dict[int, vtk.vtkPolyData] = classify(lowerTeethMesh, upperTeethMesh, missingiIds)

    # Write
    # write_obj_teeth(teethsMap, CONST_OBJ_FILENAME_OUT_12805)

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
    

    '''
    id = 1
    for T in upperTeethMesh:
        path = CONST_STL_OUTPUT + "Upper_"+ str(id) + "_tooth.stl"
        write_stl(T, path)
        id = id + 1

    id = 1
    for T in lowerTeethMesh:
        path = CONST_STL_OUTPUT + "Lower_" + str(id) + "_tooth.stl"
        write_stl(T, path)
        id = id + 1
    '''

    