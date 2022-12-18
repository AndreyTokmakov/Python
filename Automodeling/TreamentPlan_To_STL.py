
import sys
import json
import os
import logging
import warnings
import vtk
import numpy as np
from uuid import UUID

import json
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

from pytam import bindings

from pytam.io import read_from_stl, write_to_stl
from pytam.utils import transform_points
from pytam.io import KeyframeSerializer, TeethSerializer
from pytam.geometry.mesh import combine_meshes
from pytam.print_ready.create_models_for_viewer import create_stl_for_standard_viewer
from pytam.io.serialization import KeyframeSerializer, TeethSerializer
from pytam.modelling.treatment import Treatment, KeyframeType
from pytam.modelling.pdf_generation import treatment_to_dict, treatment_to_dict_v2

PATIENT_TAG_13181    = "13181"
JSON_PLAN_FILE_13181 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13181 + "/Treatment plan_01_2021-08-05-16:19:26.json"
CROWN_OBJ_FILE_13181 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13181 + "/models/3cdd_scan_crown.obj"
GUMS_OBJ_FILE_13181  = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13181 + "/models/3cdd_scan_gums.obj"

PATIENT_TAG_13078    = "13078"
JSON_PLAN_FILE_13078 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13078 + "/Treatment plan_03_2021-08-11-21:18:09.json"
CROWN_OBJ_FILE_13078 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13078 + "/models/7dc7_scan_crown.obj"
GUMS_OBJ_FILE_13078  = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13078 + "/models/7dc7_scan_gums.obj"

PATIENT_TAG_12805    = "12805"
JSON_PLAN_FILE_12805 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_12805 + "/Treatment plan_01_2021-08-12-11:10:32.json"
CROWN_OBJ_FILE_12805 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_12805 + "/models/b82b_scan_crown.obj"
GUMS_OBJ_FILE_12805  = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_12805 + "/models/b82b_scan_gums.obj"

PATIENT_TAG_13316   = "13316"
JSON_PLAN_FILE_13316 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13316 + "/Treatment plan_01_2021-08-06-14:34:37.json"
CROWN_OBJ_FILE_13316 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13316 + "/models/9899_scan_crown.obj"
GUMS_OBJ_FILE_13316  = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_13316 + "/models/9899_scan_gums.obj"

PATIENT_TAG_2287    = "2287"
JSON_PLAN_FILE_2287 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_2287 + "/Treatment plan_01_2021-02-17-04:23:08.json"
CROWN_OBJ_FILE_2287 = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_2287 + "/models/5b8e_scan_crown.obj"
GUMS_OBJ_FILE_2287  = "/home/andtokm/Projects/data/cases/" + PATIENT_TAG_2287 + "/models/5b8e_scan_gums.obj"


patientTag   = PATIENT_TAG_2287
jsonPlanFile = JSON_PLAN_FILE_2287

crownObjFile = CROWN_OBJ_FILE_2287
gumsObjFile  = GUMS_OBJ_FILE_2287

def create_files_for_standard_viewer_helper(
        json_data: Dict,
        save_to_sub_dir: bool = False):

    modelling = json_data.get('modellingData', None)
    attachments = json_data.get('attachments', [])
    separations = json_data.get('separations', [])
    visibility = json_data.get('visibility', [True] * 32)
    excursion = json_data.get('excursion', {})

    matrices = json_data.get('matrices', {'lower': [], 'upper': []})
    keyframes = KeyframeSerializer.load_list(matrices, keyf_type=KeyframeType.MATRIX)
    step_matrices = json_data.get('step_matrices', None)
    step_keyframes = KeyframeSerializer.load_step_list(step_matrices, keyf_type=KeyframeType.MATRIX)

    outDirectory = "/home/andtokm/Projects/data/cases/" + patientTag + "/out_test"
    if not Path(outDirectory).exists():
        Path(outDirectory).mkdir(parents=True, exist_ok=True)

    if modelling and keyframes:
        with open(crownObjFile, 'rt') as f:
            teeth = TeethSerializer.load_from_dict(modelling, f, visibility=visibility)
            treatment = Treatment.from_keyframes(keyframes, teeth)
            if step_matrices is not None:
                treatment_from_steps = Treatment.from_step_keyframes(step_keyframes, teeth)
                if treatment_from_steps == treatment:
                    treatment = treatment_from_steps

            attachments = TeethSerializer.load_attachments(attachments, teeth)
            separations = TeethSerializer.load_separations(separations, teeth)

            create_stl_for_standard_viewer(
                Path(gumsObjFile),
                Path(outDirectory),
                patientTag,
                treatment,
                teeth,
                attachments,
                separations,
                visibility
            )
    print(f"Output directory: {outDirectory}")


def readJsonFile(jsonFile: str)-> Dict:
    json_data: Dict
    with open(jsonFile) as json_file:
        json_data: Dict = json.load(json_file)
    return json_data;

if __name__ == '__main__':
    print("JSON --> STL")
    json = readJsonFile(jsonPlanFile)
    create_files_for_standard_viewer_helper(json)