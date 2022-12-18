
import sys
import json
import os
import logging
import warnings
import vtk
import numpy as np

from vtk.util import numpy_support
from typing import Dict, List
from pathlib import Path
from inspect import currentframe, getframeinfo
from optparse import OptionParser
from os.path import isabs, normpath
from typing import Dict
from teeth_movement.classification import classify_teeth
from teeth_movement.mesh_io import read_stl, write_obj_teeth
from teeth_movement.utils import separate_connected_components, preprocess_mesh

from pytam.io import read_from_stl, write_to_stl
from pytam.utils import transform_points
from pytam import bindings
from pytam.io import KeyframeSerializer, TeethSerializer
from pytam.geometry.mesh import combine_meshes

CONST_OBJ_FILENAME_12805 = "/home/andtokm/Projects/data/cases/12805/models/b82b_scan_crown.obj"
CONST_PLAN_JSON_12805 = "/home/andtokm/Projects/data/cases/12805/Treatment plan_01_2021-08-12-11:10:32.json"
CONST_PATIENT_HASH_12805 = 12805

CONST_OBJ_FILENAME_13078 = "/home/andtokm/Projects/data/cases/13078/models/7dc7_scan_crown.obj"
CONST_PLAN_JSON_13078 = "/home/andtokm/Projects/data/cases/13078/Treatment plan_03_2021-08-11-21:18:09.json"
CONST_PATIENT_HASH_13078 = 13078 

CONST_OBJ_FILENAME_13181 = "/home/andtokm/Projects/data/cases/13181/models/3cdd_scan_crown.obj"
CONST_PLAN_JSON_13181 = "/home/andtokm/Projects/data/cases/13181/Treatment plan_01_2021-08-05-16:19:26.json"
CONST_PATIENT_HASH_13181 = 13181

CONST_OBJ_FILENAME_13316 = "/home/andtokm/Projects/data/cases/13316/models/9899_scan_crown.obj"
CONST_PLAN_JSON_13316 = "/home/andtokm/Projects/data/cases/13316/Treatment plan_01_2021-08-06-14:34:37.json"
CONST_PATIENT_HASH_13316 = 13316

CONST_OBJ_FILENAME_2287 = "/home/andtokm/Projects/data/cases/2287/models/5b8e_scan_crown.obj"
CONST_PLAN_JSON_2287 = "/home/andtokm/Projects/data/cases/2287/Treatment plan_01_2021-02-17-04:23:08.json"
CONST_PATIENT_HASH_2287 = 2287

CONST_STL_OUTPUT = "/home/andtokm/Projects/data/cases/"

def prepare_data():
    obj_path   = Path(CONST_OBJ_FILENAME_2287)
    patiendId  = CONST_PATIENT_HASH_2287
    jsonFile   = CONST_PLAN_JSON_2287
    outputPath = CONST_STL_OUTPUT + "/" + str(patiendId) + "/automodeling/crowns"

    if not Path(outputPath).exists():
        Path(outputPath).mkdir(parents=True, exist_ok=True)

    # print("Output dir: " + outputPath)
 
    json_data: Dict
    with open(jsonFile) as json_file:
        json_data: Dict = json.load(json_file)

    modeling_data = {}
    with open(obj_path, 'rt') as f2:
        modeling_data = json_data['modellingData']
        visibility = json_data.get('visibility', [True] * 32)
        teeth = TeethSerializer.load_from_dict(modeling_data, f2, visibility=visibility)

    upper_teeth_id = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28]
    lower_teeth_id = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38]
    matrix = np.asarray([
        [-1, 0, 0, 0],
        [ 0, 0, 1, 0],
        [ 0, 1, 0, 0],
        [ 0, 0, 0, 1],
    ])

    upper_teeth_meshes = []
    for val in upper_teeth_id:
        for toothId, tooth in teeth.upper.items():
            if toothId.num == val:
                upper_teeth_meshes.append(tooth.mesh)

    upper_teeth_mesh = combine_meshes(
        upper_teeth_meshes,
        clean=False
    )

    upper_teeth_mesh.transform(matrix)

    lower_teeth_meshes = []
    for val in lower_teeth_id:
        for toothId, tooth in teeth.lower.items():
            if toothId.num == val:
                lower_teeth_meshes.append(tooth.mesh)

    lower_teeth_mesh = combine_meshes(
        lower_teeth_meshes,
        clean=False
    )

    lower_teeth_mesh.transform(matrix)

    upperCrownsSTLPath = Path(outputPath, str(patiendId) + str('_upper.stl'))
    lowerCrownsSTLPath = Path(outputPath, str(patiendId) + str('_lower.stl'))
    write_to_stl(upper_teeth_mesh, upperCrownsSTLPath)
    write_to_stl(lower_teeth_mesh, lowerCrownsSTLPath)

    print(f"Upper crowns : {upperCrownsSTLPath}")
    print(f"Lower crowns : {upperCrownsSTLPath}")

    fdi = ['11','12','13','14','15','16','17','18','21','22','23','24','25','26','27','28','31','32','33','34','35','36','37','38','41','42','43','44','45','46','47','48']
    missing_crowns = list(np.setdiff1d(fdi, list(modeling_data.keys())))

    '''
    session_config_data = {
        "paths": {
            "session_filename": str(Path(automodelling_dir, f'{hash_for_patient_tag}_automodelling_session.json')),
            "file_config": str(Path(automodelling_dir, f'{hash_for_patient_tag}_automodelling_config.json')),
            "file_u": str(upper_stl_path),
            "file_l": str(lower_stl_path),
            "dir_out": str(automodelling_dir),
            "file_t": str(Path(automodelling_dir, f'{hash_for_patient_tag}_automodelling_transformation.json'))
        },
        "hash_for_patient_tag": str(hash_for_patient_tag),
        "missing_id": [int(x) for x in missing_crowns],
        "disable_idc_find": 0,
        "t_num_l_begin": -1,
        "t_num_l_last": -1,
        "t_num_u_begin": -1,
        "t_num_u_last": -1,
        "is_test": 1,
        "b_enable_preview": 1,
        "disable_processing": 0,
        "disable_move": 0
    }

    if job.automodelling_config.json_data is not None:
        automodelling_config = job.automodelling_config.json_data
    else:
        automodelling_config = {
            "features": {
                "process_num": 0,
                "isoclines_num": 400,
                "threshold": 1.7,
                "curve_degree": 2.0
            },

            "b_silence": 0,
            "b_batching": 0,

            "upper": {
                "b_enable": 1,
                "estimator": "ellipse",
                "class": -1,

                "setup": {
                    "max_error_curve_est_percentage": 0.1,
                    "teeth_max_inter_space": 1.0,
                    "teeth_default_inter_space": 0.2,

                    "b_group_transforamtion_policy": 1,
                    "b_group_teeth_policy": 1,

                    "d_CHECK_EPS": 0.01,
                    "d_CHECK_TRANSLATION": 0.1,
                    "d_CHECK_ANGLE_DEG": 0.08
                },

                "mesh": {
                },

                "vis": {
                }
            },

            "lower": {
                "b_enable": 1,
                "estimator": "ellipse",
                "class": -1,

                "setup": {
                    "max_error_curve_est_percentage": 0.1,
                    "teeth_max_inter_space": 1.0,
                    "teeth_default_inter_space": 0.2,

                    "b_group_transforamtion_policy": 1,
                    "b_group_teeth_policy": 1,

                    "d_CHECK_EPS": 0.01,
                    "d_CHECK_TRANSLATION": 0.1,
                    "d_CHECK_ANGLE_DEG": 0.08
                },

                "mesh": {
                },

                "vis": {
                }
            },


            "setup": {
                "max_error_curve_est_percentage": 0.1,
                "teeth_max_inter_space": 1.0,
                "teeth_default_inter_space": 0.5,

                "b_move_exclude_collision": 1,

                "b_only_detect_collide": 0,
                "b_find_symmetry": 0,

                "b_setup_symmetry": 0,  # change to zero
                "d_tork_angle": 20.0,
                "d_tork_angle_lower_add": 0.0,

                "d_CHECK_EPS": 0.01,
                "d_CHECK_TRANSLATION": 0.1,
                "d_CHECK_ANGLE_DEG": 0.08,

                "n_max_stages": 200,
                "n_min_stages": 1,

                "b_group_transforamtion_policy": 0,
                "b_group_teeth_policy": 1,

                "max_translation": 0.2,
                "max_rotation": 2.0,
                "max_angulation": 1.5
            },

            "mesh": {
                "b_smooth_stl": 1,
                "n_out_poly_num": 36000,
                "n_smooth_iter": 4,
                "d_relaxation_factor": 0.1
            },

            "vis": {
                "b_mesh_vis": 0,
                "b_dental_curves_vis": 0,
                "b_curvature_vis": 0,

                "fl_axis_vis": 2,
                "n_current_teeth_vis": -1
            },

            "save": {
                "b_res": 1,
                "b_images": 0,

                "b_res_as_stl": 1,
                "b_res_each_stage": 1,
                "b_res_obj_frm": 0,
                "b_xz_plane": 0,
                "b_extract_teeth": 0
            }

        }
        #job.automodelling_config.json_data = automodelling_config

    tam_symmetry_data = {}
    fdi_upper_left_halfarch = []
    fdi_upper_right_halfarch = []
    fdi_lower_left_halfarch = []
    fdi_lower_right_halfarch = []
    for tooth_id in fdi:
        if tooth_id[0] == '1':
            fdi_upper_left_halfarch.append(tooth_id)
        if tooth_id[0] == '2':
            fdi_upper_right_halfarch.append(tooth_id)
        if tooth_id[0] == '3':
            fdi_lower_right_halfarch.append(tooth_id)
        if tooth_id[0] == '4':
            fdi_lower_left_halfarch.append(tooth_id)

    for tooth_id, tooth_data in modeling_data.items():
        # flip axes to automodelling (vtk) format
        tooth_axes = np.asarray(tooth_data['axes'], dtype=np.float64).reshape((3, 3))
        symmetry_axis = tooth_axes[2, :3]
        symmetry_axis = matrix[:3, :3] @ symmetry_axis
        angulation_axis = tooth_axes[0, :3]
        angulation_axis = matrix[:3, :3] @ angulation_axis
        tooth_origin = np.asarray(tooth_data['origin'], dtype=np.float64)
        tooth_origin = matrix[:3, :3] @ tooth_origin

        if fdi_upper_right_halfarch.count(tooth_id):
            angulation_axis[1] = -angulation_axis[1]
        elif fdi_lower_right_halfarch.count(tooth_id):
            angulation_axis = -angulation_axis
        elif fdi_lower_left_halfarch.count(tooth_id):
            angulation_axis = -angulation_axis

        tam_symmetry_data[tooth_id] = {
            "symmetry_axis": symmetry_axis.tolist(),
            "angulation_axis": angulation_axis.tolist(),
            "origin": tooth_origin.tolist()
        }

    session_json_dir = Path(automodelling_dir, f'{hash_for_patient_tag}_automodelling_session.json')
    config_json_dir = Path(automodelling_dir, f'{hash_for_patient_tag}_automodelling_config.json')
    tam_symmetry_json_dir = Path(automodelling_dir, f'tam_symmetry_{hash_for_patient_tag}.json')

    with open(session_json_dir, "w") as session_out, open(config_json_dir, "w") as config_out:
        json.dump(session_config_data, session_out)
        json.dump(automodelling_config, config_out)

    with open(tam_symmetry_json_dir, "w") as symmetry_out:
        json.dump(tam_symmetry_data, symmetry_out)

    callback_request = WorkerCallbackRequest(job_uuid, worker_token)
    result = callback_request.send_request('callback_v1_update_automodelling_config', data=automodelling_config)

    change_permissions_recursive(case_dir, 0o777)
    sleep(DELAY_TO_END)
    do_callback_request(job_uuid, worker_token, result)
    '''


if __name__ == '__main__':
    print("Preparing data")
    prepare_data();