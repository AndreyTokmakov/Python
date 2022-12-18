
# import sys
# import logging
# import warnings
# import vtk

from genericpath import exists
import os
import json
import numpy as np

from typing import Dict, List
from pathlib import Path

# from vtk.util import numpy_support
# from inspect import currentframe, getframeinfo
# from optparse import OptionParser
# from os.path import isabs, normpath

# from teeth_movement.classification import classify_teeth
# from teeth_movement.mesh_io import read_stl, write_obj_teeth
# from teeth_movement.utils import separate_connected_components, preprocess_mesh

from pytam.io import read_from_stl, write_to_stl
from pytam.io import KeyframeSerializer, TeethSerializer
from pytam.geometry.mesh import combine_meshes
from pytam.print_ready.create_models_for_viewer import create_stl_for_standard_viewer
from pytam.io.serialization import KeyframeSerializer, TeethSerializer
from pytam.modelling.treatment import Treatment, KeyframeType

# from pytam import bindings
# from pytam.utils import transform_points
# from pytam.modelling.pdf_generation import treatment_to_dict, treatment_to_dict_v2


JSON_12805 = "/home/andtokm/Projects/data/cases/" + str(12805) + "/Treatment plan_01_2021-08-12-11:10:32.json"
JSON_13078 = "/home/andtokm/Projects/data/cases/" + str(13078) + "/Treatment plan_03_2021-08-11-21:18:09.json"
JSON_13181 = "/home/andtokm/Projects/data/cases/" + str(13181) + "/Treatment plan_01_2021-08-05-16:19:26.json"
JSON_13316 = "/home/andtokm/Projects/data/cases/" + str(13316) + "/Treatment plan_01_2021-08-06-14:34:37.json"
JSON_2287 = "/home/andtokm/Projects/data/cases/" + str(2287) + "/Treatment plan_01_2021-02-17-04:23:08.json"
JSON_2333 = "/home/andtokm/Projects/data/cases/" + str(2333) + "/Treatment plan_01_2021-02-18-22:40:50.json"
JSON_2579 = "/home/andtokm/Projects/data/cases/" + str(2579) + "/Treatment plan_01_2021-04-14-19:07:10.json"
JSON_2600 = "/home/andtokm/Projects/data/cases/" + str(2600) + "/Treatment plan_02_2021-05-15-16:24:00.json"
JSON_2622 = "/home/andtokm/Projects/data/cases/" + str(2622) + "/Treatment plan_03_2021-05-06-22:37:05.json"
JSON_2630 = "/home/andtokm/Projects/data/cases/" + str(2630) + "/Treatment plan_01_2021-04-27-22:16:34.json"
JSON_2636 = "/home/andtokm/Projects/data/cases/" + str(2636) + "/Treatment plan_01_2021-05-03-21:12:41.json"
JSON_2195 = "/home/andtokm/Projects/data/cases/" + str(2195) + "/Correction_01_2021-07-19-10:34:08.json"
JSON_2457 = "/home/andtokm/Projects/data/cases/" + str(2457) + "/Treatment plan_01_2021-07-20-21:33:38.json"
JSON_2705 = "/home/andtokm/Projects/data/cases/" + str(2705) + "/Treatment plan_01_2021-05-17-19:36:11.json"
JSON_2812 = "/home/andtokm/Projects/data/cases/" + str(2812) + "/Treatment plan_01_2021-06-25-15:24:51.json"
JSON_2878 = "/home/andtokm/Projects/data/cases/" + str(2878) + "/Treatment plan_01_2021-07-15-15:43:00.json"
JSON_6821 = "/home/andtokm/Projects/data/cases/" + str(6821) + "/plan.json"
JSON_13789 = "/home/andtokm/Projects/data/cases/" + str(13789) + "/Plan.json"
JSON_13758 = "/home/andtokm/Projects/data/cases/" + str(13758) + "/Plan_13758.json"
JSON_10379 = "/home/andtokm/Projects/data/cases/" + str(10379) + "/Correction_01_2021-04-07-16:50:56.json"

###########################################################################################################################

class CasesDirWorker(object):

    CASES_ROOT_DIR  = "/home/andtokm/Projects/data/cases"
    MODELS_DIR_NAME = "models"
    AUTOMODELING_DIR_NAME = "automodeling"
    AUTOMODELING_CROWNS_DIR_NAME = "crowns"

    CROWNS_OBJ_SCAN_MASK = '_scan_crown.obj'
    GUMS_OBJ_SCAN_MASK   = '_scan_gums.obj'

    TREATMENT_PLAN_PREFIX  = 'Treatment'
    TREATMENT_PLAN_POSTFIX  = '.json'

    def __init__(self, patientId: int,
                       treatment_plan_path: str) -> None:
        super().__init__()
        self.__patientId = str(patientId);
        self.__treatment_plan_path = treatment_plan_path;

    def getPatientId(self) -> str:
        return self.__patientId

    def getCasesRootFolder(self) -> str:
        return self.CASES_ROOT_DIR

    def getModelingOutputFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, "out_test")

    def getAutoModelingFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.AUTOMODELING_DIR_NAME)               

    def getAutoModelingCrownsFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.AUTOMODELING_DIR_NAME, self.AUTOMODELING_CROWNS_DIR_NAME)

    def getCrownObjModel(self):
        modelsDirPath = os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.MODELS_DIR_NAME)
        with os.scandir(modelsDirPath) as dirs:
            files = [entry for entry in dirs if os.path.isfile(os.path.join(modelsDirPath, entry))]
        crownObjs = [file.path for file in files if file.name.endswith(self.CROWNS_OBJ_SCAN_MASK)]

        if (1 == len(crownObjs)):
            return crownObjs[0]
        return None

    def getGumsObjModel(self):
        modelsDirPath = os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.MODELS_DIR_NAME)
        with os.scandir(modelsDirPath) as dirs:
            files = [entry for entry in dirs if os.path.isfile(os.path.join(modelsDirPath, entry))]
        gumsFiles = [file.path for file in files if file.name.endswith(self.GUMS_OBJ_SCAN_MASK)]

        if (1 == len(gumsFiles)):
            return gumsFiles[0]
        return None

    def getTreatmentPlan(self):
        '''
        modelsDirPath = os.path.join(self.CASES_ROOT_DIR, self.__patientId)
        with os.scandir(modelsDirPath) as dirs:
            files = [entry for entry in dirs if os.path.isfile(os.path.join(modelsDirPath, entry))]

        plansFiles = []
        for file in files:
            if file.name.startswith(self.TREATMENT_PLAN_PREFIX) and file.name.endswith(self.TREATMENT_PLAN_POSTFIX):
                plansFiles.append(file.path);

        for F in plansFiles:
            print(F)
        '''

        return self.__treatment_plan_path




def create_files_for_standard_viewer_helper(caseDir: CasesDirWorker):
    jsonObject: Dict  = dict()
    with open(caseDir.getTreatmentPlan()) as json_file:
        jsonObject: Dict = json.load(json_file)

    modelling   = jsonObject.get('modellingData', None)
    attachments = jsonObject.get('attachments', [])
    separations = jsonObject.get('separations', [])
    visibility  = jsonObject.get('visibility', [True] * 32)
    # excursion   = jsonObject.get('excursion', {})

    matrices = jsonObject.get('matrices', {'lower': [], 'upper': []})
    keyframes = KeyframeSerializer.load_list(matrices, keyf_type=KeyframeType.MATRIX)
    step_matrices = jsonObject.get('step_matrices', None)
    step_keyframes = KeyframeSerializer.load_step_list(step_matrices, keyf_type=KeyframeType.MATRIX)

    outDirectory = caseDir.getModelingOutputFolder()
    if not Path(outDirectory).exists():
        Path(outDirectory).mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {outDirectory}")

    if modelling and keyframes:
        with open(caseDir.getCrownObjModel(), 'rt') as f:
            teeth = TeethSerializer.load_from_dict(modelling, f, visibility=visibility)
            treatment = Treatment.from_keyframes(keyframes, teeth)
            if step_matrices is not None:
                treatment_from_steps = Treatment.from_step_keyframes(step_keyframes, teeth)
                if treatment_from_steps == treatment:
                    treatment = treatment_from_steps

            attachments = TeethSerializer.load_attachments(attachments, teeth)
            separations = TeethSerializer.load_separations(separations, teeth)

            create_stl_for_standard_viewer(Path(caseDir.getGumsObjModel()),
                                           Path(outDirectory),
                                           caseDir.getPatientId(),
                                           treatment,
                                           teeth,
                                           attachments,
                                           separations,
                                           visibility)
    


''' Prapare STL data (crowns) from Treament plan and Crowns.OBJ: '''
def prepare_data(caseDir: CasesDirWorker):
    crownsObjFile = Path(caseDir.getCrownObjModel())

    outputPath  = caseDir.getAutoModelingCrownsFolder()
    if not Path(outputPath).exists():
        Path(outputPath).mkdir(parents=True, exist_ok=True)

    json_data: Dict
    with open(caseDir.getTreatmentPlan()) as json_file:
        json_data: Dict = json.load(json_file)

    modeling_data = {}
    with open(crownsObjFile, 'rt') as f2:
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

    upperCrownsSTLPath = Path(outputPath, caseDir.getPatientId() + str('_upper.stl'))
    lowerCrownsSTLPath = Path(outputPath, caseDir.getPatientId() + str('_lower.stl'))
    write_to_stl(upper_teeth_mesh, upperCrownsSTLPath)
    write_to_stl(lower_teeth_mesh, lowerCrownsSTLPath)

    print(f"Upper crowns : {upperCrownsSTLPath}")
    print(f"Lower crowns : {upperCrownsSTLPath}")

    # fdi = ['11','12','13','14','15','16','17','18','21','22','23','24','25','26','27','28','31','32','33','34','35','36','37','38','41','42','43','44','45','46','47','48']
    # missing_crowns = list(np.setdiff1d(fdi, list(modeling_data.keys())))



''' Prapare STL data (crowns) from Treament plan and Crowns.OBJ: '''
def prepare_data_no_transform(caseDir: CasesDirWorker):
    crownsObjFile = Path(caseDir.getCrownObjModel())

    outputPath  = caseDir.getAutoModelingCrownsFolder().replace('crowns', 'crowns_no_transform')
    if not Path(outputPath).exists():
        Path(outputPath).mkdir(parents=True, exist_ok=True)

    json_data: Dict
    with open(caseDir.getTreatmentPlan()) as json_file:
        json_data: Dict = json.load(json_file)

    modeling_data = {}
    with open(crownsObjFile, 'rt') as f2:
        modeling_data = json_data['modellingData']
        visibility = json_data.get('visibility', [True] * 32)
        teeth = TeethSerializer.load_from_dict(modeling_data, f2, visibility=visibility)

    upper_teeth_id = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28]
    lower_teeth_id = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38]
    
    upper_teeth_meshes = []
    for val in upper_teeth_id:
        for toothId, tooth in teeth.upper.items():
            if toothId.num == val:
                upper_teeth_meshes.append(tooth.mesh)

    upper_teeth_mesh = combine_meshes(
        upper_teeth_meshes,
        clean=False
    )

    lower_teeth_meshes = []
    for val in lower_teeth_id:
        for toothId, tooth in teeth.lower.items():
            if toothId.num == val:
                lower_teeth_meshes.append(tooth.mesh)

    lower_teeth_mesh = combine_meshes(
        lower_teeth_meshes,
        clean=False
    )

    upperCrownsSTLPath = Path(outputPath, caseDir.getPatientId() + str('_upper.stl'))
    lowerCrownsSTLPath = Path(outputPath, caseDir.getPatientId() + str('_lower.stl'))
    write_to_stl(upper_teeth_mesh, upperCrownsSTLPath)
    write_to_stl(lower_teeth_mesh, lowerCrownsSTLPath)

    print(f"Upper crowns : {upperCrownsSTLPath}")
    print(f"Lower crowns : {upperCrownsSTLPath}")


''' Extract missing teeth from the Treatment plan json file. '''
def get_missing_teehs(caseDir: CasesDirWorker) -> List:
    jsonObject: Dict  = dict()
    with open(caseDir.getTreatmentPlan()) as json_file:
        jsonObject: Dict = json.load(json_file)

    modelling_data = jsonObject.get('modellingData', None)
    existing_teeth = set([int(k) for k, v in modelling_data.items()])

    all_teeth = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28, 
                 48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38 }

    return list(all_teeth.difference(existing_teeth))

 
''' Craete config files: '''
def create_config_files(caseDir: CasesDirWorker):
    missing_teeth = get_missing_teehs(caseDir)
    patient_id = casesDir.getPatientId()
    folder = casesDir.getAutoModelingFolder()

    with open(os.path.join("templates", "session_template.json"), 'r') as file:
        text = file.readlines()

    config = []
    for line in text:
        config.append(line.replace("<CASE_ID>", patient_id).replace("<MISSING_IDS>", str(missing_teeth)))

    # Creating a file at specified location
    with open(os.path.join(folder, f"{patient_id}_session.json"), 'w') as file:
        for line in config:
            file.write(line)


    with open(os.path.join("templates", "config_template.json"), 'r') as file:
        text = file.readlines()

    # Creating a file at specified location
    with open(os.path.join(folder, f"{patient_id}_config.json"), 'w') as file:
        for line in text:
            file.write(line)            



''' Main '''
if __name__ == '__main__':
    casesDir = CasesDirWorker(2705, JSON_2705);

    '''Convert Treatment plan ---> production movment results in STL '''
    create_files_for_standard_viewer_helper(casesDir)

    ''' Convert Treatment plan ---> production movment results in STL '''
    prepare_data(casesDir)
    # prepare_data_no_transform(casesDir);

    ''' Prepare config files: '''
    create_config_files(casesDir)


