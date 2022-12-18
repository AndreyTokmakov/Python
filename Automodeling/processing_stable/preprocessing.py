
import os
import vtk
import json
import logging
import warnings
import numpy as np

#from os.path import isabs, normpath
from typing import Dict
from typing import Dict, List
from utils import get_centroid, list_diff, separate_connected_components, preprocess_mesh
from mesh_io import read_stl, write_obj_teeth, read_stl, write_obj_teeth

warnings.simplefilter(action='ignore', category=FutureWarning)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('symmetry')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

def classify_teeth(lower_teeth_meshes: List[vtk.vtkPolyData],
                   upper_teeth_meshes: List[vtk.vtkPolyData],
                   missing_teeth_id: List[int]) -> Dict[int, vtk.vtkPolyData]:
    """
    Classify teeth meshes based on centroids.

    You'll need to specify id of missing teeth in format: ::

        [16, ]

    Return result in format ::

        {
            18: vtk.vtkPolyData,
            17: vtk.vtkPolyData,
            ...
        }

    Algorithm description:

    3D scene coordinate space:
    - Z is up (Patient superior)

    We assume that the centroid for the molars is smaller on Y axis than the incisors
    Y axis positive points to anterior direction
    Y axis negative points to posterior direction

    X axis positive points to patient left direction
    X axis negative points to patient right direction

    NB! By default the script accepts models that have the axes encoded in the following order:
    [XZY]
    This is the same axes encoding format that 3D Smile V3 viewer accepts.

    1. Compute centroids
    2. Select teeth to classify based on Y coordinate
    3. Sort their centroids by Y coordinate and match them with id
    4. Select teeth to classify based on X coordinate
    5. Sort their centroids by X coordinate and match them with id

    :param lower_teeth_meshes: mesh for each crown of lower jaw
    :param upper_teeth_meshes: mesh for each crown of upper jaw
    :param missing_teeth_id: id of missing teeth
    :return map from tooth id to mesh.
    """
    id_cenrtoid_dict = {}

    # teeth ID in FDI notation
    lower_id = tuple(range(48, 40, -1)) + tuple(range(38, 30, -1))
    upper_id = tuple(range(18, 10, -1)) + tuple(range(28, 20, -1))
    # teeth to classify based on X coordinate
    x_group_lower_id = (43, 42, 41, 31, 32, 33)
    x_group_upper_id = (13, 12, 11, 21, 22, 23)
    # teeth to classify based on Y coordinate
    left_group_lower_id = (48, 47, 46, 45, 44)
    left_group_upper_id = (18, 17, 16, 15, 14)

    # if number of connected components != number of teeth raise ValueError
    if len(list_diff(lower_id + upper_id, missing_teeth_id)) !=\
           len(lower_teeth_meshes) + len(upper_teeth_meshes):               
        raise ValueError(f'Wrong missing teeth specification, lower {len(lower_teeth_meshes)}, upper {len(upper_teeth_meshes)}')

    # compute crown centroids
    centroids_lower = np.zeros((len(lower_teeth_meshes), 4))
    centroids_upper = np.zeros((len(upper_teeth_meshes), 4))
    for i, tooth_model in enumerate(lower_teeth_meshes):
        centroids_lower[i, :3] = get_centroid(tooth_model)
        centroids_lower[i, 3] = i
    for i, tooth_model in enumerate(upper_teeth_meshes):
        centroids_upper[i, :3] = get_centroid(tooth_model)
        centroids_upper[i, 3] = i

    for centroids, id_list, x_group_id, left_group_id in zip(
            [centroids_lower, centroids_upper],
            [lower_id, upper_id],
            [x_group_lower_id, x_group_upper_id],
            [left_group_lower_id, left_group_upper_id]):
        # find id of teeth to classify based on Y coordinate
        y_group_id = list_diff(id_list, x_group_id)
        right_group_id = list_diff(y_group_id, left_group_id)
        y_group_missing_id = list(set(missing_teeth_id).intersection(y_group_id))
        y_group_id = list_diff(y_group_id, y_group_missing_id)

        # find mean X coordinate
        x_mean = centroids[:, 0].mean()
        centroids_left = centroids[centroids[:, 0] < x_mean]
        centroids_right = centroids[centroids[:, 0] >= x_mean]

        # sort by Y coodinate
        centroids_sorted_left = centroids_left[centroids_left[:, 2].argsort()]
        centroids_sorted_right = centroids_right[centroids_right[:, 2].argsort()]
        centroids_y_sorted_left = centroids_sorted_left[
                :5 - len(set(y_group_missing_id).intersection(left_group_id))]
        centroids_y_sorted_right = centroids_sorted_right[
                :5 - len(set(y_group_missing_id).intersection(right_group_id))]

        # classify based on Y coordinate
        centroids_y = np.concatenate([centroids_y_sorted_left, centroids_y_sorted_right], axis=0)
        for i, y_id in enumerate(y_group_id):
            id_cenrtoid_dict[y_id] = centroids_y[i]

        # sort by X coordinate
        centroids_x_left = centroids_sorted_left[
                5 - len(set(y_group_missing_id).intersection(left_group_id)):]
        centroids_x_right = centroids_sorted_right[
                5 - len(set(y_group_missing_id).intersection(right_group_id)):]
        centroids_x = np.concatenate([centroids_x_left, centroids_x_right], axis=0)

        # classify based on X coordinates
        centroids_x = centroids_x[centroids_x[:, 0].argsort()]
        x_group_id = list_diff(x_group_id, missing_teeth_id)
        for i, x_id in enumerate(x_group_id):
            id_cenrtoid_dict[x_id] = centroids_x[i]

    # create resulting dict
    id_model_dict = {}
    for tooth_id in id_cenrtoid_dict:
        if tooth_id in lower_id:
            id_model_dict[tooth_id] = lower_teeth_meshes[
                    int(id_cenrtoid_dict[tooth_id][3])]
        elif tooth_id in upper_id:
            id_model_dict[tooth_id] = upper_teeth_meshes[
                    int(id_cenrtoid_dict[tooth_id][3])]
    return id_model_dict


if __name__ == '__main__':
    import sys
    from pathlib import Path
    from inspect import currentframe, getframeinfo
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-s", "--session",
                    action="store",
                    dest="session_filename",
                    help="set session file path name",
                    metavar="FILE")
    parser.add_option("-c", "--config", 
                    action="store",
                    dest="config_filename",
                    help="set config file path name", 
                    metavar="FILE")
    parser.add_option("-q", "--quiet",
                    action="store",
                    dest="verbose",
                    default=1,
                    type='int',
                    help="set log 0=get environ LOG_LEVEL, 1=DEBUG, 2, 3, 4, 5=FATAL [default: 1]")

    (options, args) = parser.parse_args()

    level = logging.INFO
    if 0 != options.verbose :
        levels = { 
            1 : logging.DEBUG,
            2 : logging.INFO,
            3 : logging.WARNING,
            4 : logging.ERROR,
            5 : logging.FATAL
        }
        if options.verbose > 0 and options.verbose <= 5 : 
            level = levels[options.verbose]
    else:
        level = logging.getLevelName(os.environ.get('LOG_LEVEL', 'INFO'))

    log.setLevel(level=level)
    log.info(f'log level: {logging.getLevelName(level)}')

    #log.debug(f' : {options} : {args}')

    # Read session configuration
    directory = Path(getframeinfo(currentframe()).filename).resolve().parents[0]

    session_filename = options.session_filename
    if not session_filename:
        session_filename = directory / 'session.json'
    log.info(f'session filename : {session_filename}')
    
    session_config_data = json.load(open(session_filename, 'rt'))

    config_filename = options.config_filename 
    if not config_filename:
        config_filename = session_config_data['paths']['file_config'] 
    if not os.path.isabs(config_filename):
        config_filename = os.path.normpath(directory / config_filename)
    log.info(f'TEST1 config filename : {config_filename}')
    config_data = json.load(open(config_filename, 'rt'))
    config_data = config_data['features']

    case_id = session_config_data['hash_for_patient_tag']

    # directory_out = os.path.join(session_config_data['paths']['dir_out'], case_id)
    directory_out = session_config_data['paths']['dir_out']
    if not os.path.isabs(directory_out):
        directory_out = os.path.normpath(directory / directory_out) 
    if not os.path.exists(directory_out):
        try:
            os.makedirs(directory_out, exist_ok=True)
        except OSError as exception:
            log.error(f'output directory : {directory_out} not create')
            sys.exit(2)
    log.info(f'out directory : {directory_out}')

    upper_model_path = session_config_data['paths']['file_u']
    if not os.path.isabs(upper_model_path):
        upper_model_path = os.path.normpath(directory / upper_model_path) 
    log.info(f'file upper : {upper_model_path}')

    lower_model_path = session_config_data['paths']['file_l']
    if not os.path.isabs(lower_model_path):
        lower_model_path = os.path.normpath(directory / lower_model_path) 
    log.info(f'file lower : {lower_model_path}')   

    missing_id = session_config_data['missing_id']

    log.info(f'missing_id : {missing_id}')
    log.info(f'hash_for_patient_tag : {case_id}')

    # read crowns from STL models
    lower_teeth_mesh = read_stl(lower_model_path)
    upper_teeth_mesh = read_stl(upper_model_path)

    if not lower_teeth_mesh.GetNumberOfPoints() and not upper_teeth_mesh.GetNumberOfPoints():
        log.error('error load models')   
        sys.exit(1)

    OUT_POLY_COEF = 0.8
    if "out_poly_coef" in config_data:
        out_poly_coef = config_data['out_poly_coef']
        log.info(f'out_poly_coef : {OUT_POLY_COEF}')
    else:
        log.info(f'out_poly_coef not def, set default: {OUT_POLY_COEF}')

    ITER_NUM = 2 # 2 org #4 incr if bad symmetry_axis
    if "iter_num" in config_data:
        out_poly_coef = config_data['iter_num']
        log.info(f'iter_num : {ITER_NUM}')
    else:
        log.info(f'iter_num not def, set default: {ITER_NUM}')

    RELAXATION_FACTOR = 0.1 # 0.01            
    if "relaxation_factor" in config_data:
        out_poly_coef = config_data['relaxation_factor']
        log.info(f'relaxation_factor : {RELAXATION_FACTOR}')
    else:
        log.info(f'relaxation_factor not def, set default: {RELAXATION_FACTOR}')

    OUT_POLY_NUM = 60000
    if "out_poly_num" in config_data:
        out_poly_coef = config_data['out_poly_num']
        log.info(f'out_poly_num : {OUT_POLY_NUM}')
    else:
        log.info(f'out_poly_num not def, set default: {OUT_POLY_NUM}')

    lower_teeth_mesh = preprocess_mesh(lower_teeth_mesh, log, 
                                    ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)
    upper_teeth_mesh = preprocess_mesh(upper_teeth_mesh, log, 
                                    ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)

    # classify
    teeth_map = classify_teeth(
        separate_connected_components(lower_teeth_mesh),
        separate_connected_components(upper_teeth_mesh),
        missing_id
    )

    '''
    CONST_STL_OUTPUT = "/home/andtokm/Projects/data/out/"
    upperToothIds = (11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28)
    lowerToothIds = (41, 42, 43, 44, 45, 46, 47, 48, 31, 32, 33, 34, 35, 36, 37, 38)
    for k, v in teeth_map.items():
        if k in lowerToothIds:
            path = CONST_STL_OUTPUT + "Lower_"+ str(k) + "_tooth.stl"
            write_stl(v, path)
        if k in upperToothIds:
            path = CONST_STL_OUTPUT + "Upper_"+ str(k) + "_tooth.stl"
            write_stl(v, path)
    '''

    # compute oriented bounding boxes
    '''
    bbox_map = {}
    for key, mesh in teeth_map.items():
        corner, max_axis, mid_axis, min_axis, size = ([0.0, 0.0, 0.0] for i in range(5))
        vtk.vtkOBBTree.ComputeOBB(
            mesh.GetPoints(),
            corner,
            max_axis,
            mid_axis,
            min_axis,
            size
        )
        bbox_map[key] = {
            'corner': corner,
            'max_axis': max_axis,
            'mid_axis': mid_axis,
            'min_axis': min_axis,
        }

    # write bounding boxes to JSON
    json.dump(
        bbox_map,
        open(os.path.join(
            directory_out, f'{case_id}_bboxes.json'
        ), 'wt')
    )
    '''

    # write classified crowns to OBJ
    write_obj_teeth(
        teeth_map,
        os.path.join(
            directory_out, f'{case_id}_teeth.obj'
        )
    )
