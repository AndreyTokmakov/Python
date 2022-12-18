import csv
import argparse
import shutil
import subprocess
import os
import json
import tarfile

import numpy as np

from typing import Dict, List, Set
from pathlib import Path
from genericpath import exists

import sys
from pytam.io import read_from_stl, write_to_stl
from pytam.io import KeyframeSerializer, TeethSerializer
from pytam.geometry.mesh import combine_meshes
from pytam.print_ready.create_models_for_viewer import create_stl_for_standard_viewer
from pytam.io.serialization import KeyframeSerializer, TeethSerializer
from pytam.modelling.treatment import Treatment, KeyframeType


###########################################################################################################################

class CasesDirWorker(object):
    CASES_FOLDER_NAME = "cases_ml"
    CASES_ROOT_DIR = f'/home/andtokm/Projects/data/{CASES_FOLDER_NAME}'
    MODELS_DIR_NAME = "models"
    AUTOMODELING_DIR_NAME = "automodeling"
    PROCESSED_MODEL_DIR_NAME = "processed"
    AUTOMODELING_CROWNS_DIR_NAME = "crowns"

    CROWNS_OBJ_SCAN_MASK = '_scan_crown.obj'
    GUMS_OBJ_SCAN_MASK = '_scan_gums.obj'

    TREATMENT_PLAN_PREFIX = 'Treatment plan_'
    CORRECTION_PREFIX = 'Correction_'
    TREATMENT_PLAN_POSTFIX = '.json'

    TOOTH_MODELS_FILE_POSTFIX = " - Model.stl"
    TEMPLATE_TOOTH_MODEL_POSTFIX = "Template.stl"
    LOWER_TOOTH_MODELS_PREFIX = "lower - "
    UPPER_TOOTH_MODELS_PREFIX = "upper - "

    def __init__(self, patientId: str) -> None:
        super().__init__()

        self.__plansFiles = []
        self.__planLatest = None
        self.__lowerModelFinal = None
        self.__upperModelFinal = None

        self.__patientId = patientId;
        self.__init_plans_list()

    def __init_plans_list(self):
        modelsDirPath = os.path.join(self.CASES_ROOT_DIR, str(self.__patientId))
        with os.scandir(modelsDirPath) as dirs:
            files = [entry for entry in dirs if os.path.isfile(os.path.join(modelsDirPath, entry))]

        print(len(self.__plansFiles))

        # Get all JSON files with names starting with 'Treatment' or 'Correction'
        for file in files:
            if (file.name.startswith(self.TREATMENT_PLAN_PREFIX) or file.name.startswith(self.CORRECTION_PREFIX)) and \
                    file.name.endswith(self.TREATMENT_PLAN_POSTFIX):
                self.__plansFiles.append(file.path)

        # Determine prefix name
        # It could be 'Treatment' or 'Correction'
        prefix = None
        if [s for s in self.__plansFiles if self.TREATMENT_PLAN_PREFIX in s]:
            prefix = self.TREATMENT_PLAN_PREFIX
        elif [s for s in self.__plansFiles if self.CORRECTION_PREFIX in s]:
            prefix = self.CORRECTION_PREFIX

        maxId = -1;
        for planName in self.__plansFiles:
            prefixLength = len(prefix)
            startPos = planName.find(prefix)
            endPos = planName.find("_", startPos + prefixLength)
            planNumber = int(planName[startPos + prefixLength: endPos])
            if planNumber > maxId:
                self.__planLatest = planName
                maxId = planNumber

    def getPatientId(self) -> str:
        return self.__patientId

    def getCasesRootFolder(self) -> str:
        return self.CASES_ROOT_DIR

    def getModelingOutputFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, "out_test")

    def getAutoModelingFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.AUTOMODELING_DIR_NAME)

    def getAutoModelingCrownsFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.AUTOMODELING_DIR_NAME,
                            self.AUTOMODELING_CROWNS_DIR_NAME)

    # Return folder where processed models shall be stored
    # Processed by technician specialist
    def getProcessedModelFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.PROCESSED_MODEL_DIR_NAME)

    # Return folder where processed models shall be stored
    # Processed by technician specialist
    def getProcessedModelCrownsFolder(self) -> str:
        return os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.PROCESSED_MODEL_DIR_NAME,
                            self.AUTOMODELING_CROWNS_DIR_NAME)

    def getCrownObjModel(self):
        modelsDirPath = os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.MODELS_DIR_NAME)
        with os.scandir(modelsDirPath) as dirs:
            files = [entry for entry in dirs if os.path.isfile(os.path.join(modelsDirPath, entry))]
        crownObjs = [file.path for file in files if file.name.endswith(self.CROWNS_OBJ_SCAN_MASK)]

        if 1 == len(crownObjs):
            return crownObjs[0]
        return None

    def getGumsObjModel(self):
        modelsDirPath = os.path.join(self.CASES_ROOT_DIR, self.__patientId, self.MODELS_DIR_NAME)
        with os.scandir(modelsDirPath) as dirs:
            files = [entry for entry in dirs if os.path.isfile(os.path.join(modelsDirPath, entry))]
        gumsFiles = [file.path for file in files if file.name.endswith(self.GUMS_OBJ_SCAN_MASK)]

        if 1 == len(gumsFiles):
            return gumsFiles[0]
        return None

    def getTreatmentPlan(self):
        return self.__planLatest

    def __extract_tooth_stl_file_id(self, file_path: str, prefix: str) -> int:
        start = file_path.find(prefix) + len(prefix)
        end = file_path.find(self.TOOTH_MODELS_FILE_POSTFIX, start)
        return int(file_path[start: end])

    def __get_template_and_model_tooth_files(self, files: List, prefix: str) -> List:
        maxId = -1;
        models_list = [None] * 2
        for file in files:
            if self.TEMPLATE_TOOTH_MODEL_POSTFIX in file:
                models_list[0] = file
            else:
                modelId = self.__extract_tooth_stl_file_id(file, prefix)
                if modelId > maxId:
                    maxId = modelId;
                    models_list[1] = file
        return models_list

    # Removes "out_test/locks", "out_test/gums", "out_test/torque_controllers" folders
    # Removes out_test/teeth/*.stl models except '*_Template.stl' and '<ID_MAX>- Model.stl'
    def removeExcessFiles(self):
        with os.scandir(self.getModelingOutputFolder()) as dirs:
            dirs = [entry for entry in dirs if os.path.isdir(entry)]

        teethFolder = None
        for entry in dirs:  # Delete "locks", "gums" and "torque_controllers" folders:
            if entry.name in ["locks", "gums", "torque_controllers"]:
                shutil.rmtree(entry.path, ignore_errors=True)
            if entry.name == "teeth":
                teethFolder = entry

        if teethFolder is None:
            return
        with os.scandir(teethFolder) as dirs:
            files = [entry for entry in dirs if os.path.isfile(entry)]

        lowerFiles = [entry.path for entry in files if self.LOWER_TOOTH_MODELS_PREFIX in entry.path]
        upperFiles = [entry.path for entry in files if self.UPPER_TOOTH_MODELS_PREFIX in entry.path]
        lowerFilesFinal = self.__get_template_and_model_tooth_files(lowerFiles, self.LOWER_TOOTH_MODELS_PREFIX)
        upperFilesFinal = self.__get_template_and_model_tooth_files(upperFiles, self.UPPER_TOOTH_MODELS_PREFIX)

        self.__lowerModelFinal = lowerFilesFinal[1]
        self.__upperModelFinal = upperFilesFinal[1]

        for model_file in lowerFiles:
            if model_file not in lowerFilesFinal:
                os.remove(model_file)
        for model_file in upperFiles:
            if model_file not in upperFilesFinal:
                os.remove(model_file)

    def copyProcessedModels(self):
        outDirectory = self.getProcessedModelCrownsFolder()
        if not Path(outDirectory).exists():
            Path(outDirectory).mkdir(parents=True, exist_ok=True)

        dst = f'{outDirectory}/{self.__patientId}_lower.stl'
        shutil.copyfile(self.__lowerModelFinal, dst)

        dst = f'{outDirectory}/{self.__patientId}_upper.stl'
        shutil.copyfile(self.__upperModelFinal, dst)


###########################################################################################

def create_files_for_standard_viewer_helper(caseDir: CasesDirWorker):
    jsonObject: Dict = dict()
    with open(caseDir.getTreatmentPlan()) as json_file:
        jsonObject: Dict = json.load(json_file)

    modelling = jsonObject.get('modellingData', None)
    attachments = jsonObject.get('attachments', [])
    separations = jsonObject.get('separations', [])
    visibility = jsonObject.get('visibility', [True] * 32)
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

    outputPath = caseDir.getAutoModelingCrownsFolder()
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
        [0, 0, 1, 0],
        [0, 1, 0, 0],
        [0, 0, 0, 1],
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

    outputPath = caseDir.getAutoModelingCrownsFolder().replace('crowns', 'crowns_no_transform')
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
    jsonObject: Dict = dict()
    with open(caseDir.getTreatmentPlan()) as json_file:
        jsonObject: Dict = json.load(json_file)

    modelling_data = jsonObject.get('modellingData', None)
    existing_teeth = set([int(k) for k, v in modelling_data.items()])

    all_teeth = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28,
                 48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}

    return list(all_teeth.difference(existing_teeth))


''' Craete config files: '''


def create_config_files(casesDir: CasesDirWorker):
    missing_teeth = get_missing_teehs(casesDir)
    patient_id = casesDir.getPatientId()
    folder = casesDir.getAutoModelingFolder()

    with open(os.path.join("templates", "session_template_ML.json"), 'r') as file:
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


''' Craete config files: '''


def create_processed_models_config_files(casesDir: CasesDirWorker):
    missing_teeth = get_missing_teehs(casesDir)
    patient_id = casesDir.getPatientId()
    folder = casesDir.getProcessedModelFolder()

    with open(os.path.join("templates", "session_template_ML_processed.json"), 'r') as file:
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


def execute(cmd: str):
    process = subprocess.Popen(cmd,
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               universal_newlines=True)
    while True:
        output = process.stdout.readline()
        print(output.strip())
        # Do something else
        return_code = process.poll()
        if return_code is not None:
            # Process has finished, read rest of the output
            for output in process.stdout.readlines():
                print(output.strip())
            break
    return process.wait()

##############################################################################################################

def processCase_UserInput():
    # Instantiate the parser
    parser = argparse.ArgumentParser(description='Optional app description')
    parser.add_argument('case_id', type=int, help='Case ID')
    args = parser.parse_args()

    caseId = args.case_id
    casesDir = CasesDirWorker(caseId)

    # Convert Treatment plan ---> production movement results in STL
    create_files_for_standard_viewer_helper(casesDir)

    # Convert Treatment plan ---> production movement results in STL
    prepare_data(casesDir)
    # prepare_data_no_transform(casesDir);

    # Remove excess files and folders:
    casesDir.removeExcessFiles()

    # Copy manual-made models to new destination folder + rename them
    casesDir.copyProcessedModels()

    # Prepare config files:
    create_config_files(casesDir)
    create_processed_models_config_files(casesDir);

    sessionPath = f'~/Projects/data/cases_ml/{caseId}/automodeling/{caseId}_session.json'
    sessionPathProcessed = f'~/Projects/data/cases_ml/{caseId}/processed/{caseId}_session.json'
    handlers = ['processing_stable/preprocessing.py',
                'processing_stable/extract_features.py',
                'processing_stable/symmetry.py']

    params = f'-s {sessionPath}'
    for handler in handlers:
        cmd = f'python3 {handler} {params}'
        print(f'===================== {cmd} ========================')
        execute(cmd)

    params = f'-s {sessionPathProcessed}'
    for handler in handlers:
        cmd = f'python3 {handler} {params}'
        print(f'===================== {cmd} ========================')
        execute(cmd)


def CopyArtefactsAndClenup(casesDir: CasesDirWorker):
    processedOutFolder = f"{casesDir.getProcessedModelFolder()}/out"
    with os.scandir(processedOutFolder) as files:
        processedJSONs = [entry for entry in files if os.path.isfile(entry) and ".json" in entry.name]

    automodelFolder = f"{casesDir.getAutoModelingFolder()}/out"
    with os.scandir(automodelFolder) as files:
        automodeljSONs = [entry for entry in files if os.path.isfile(entry) and ".json" in entry.name]

    caseId = casesDir.getPatientId()
    caseDir = f'{casesDir.getCasesRootFolder()}/{caseId}'
    caseDirTmp = f'{casesDir.getCasesRootFolder()}/__{caseId}'
    beforeDir = f'{caseDirTmp}/before'
    afterDir = f'{caseDirTmp}/after'

    Path(beforeDir).mkdir(parents=True, exist_ok=True)
    Path(afterDir).mkdir(parents=True, exist_ok=True)

    for entry in automodeljSONs:
        shutil.move(entry.path, f'{beforeDir}/{entry.name}')
    for entry in processedJSONs:
        shutil.move(entry.path, f'{afterDir}/{entry.name}')

    shutil.move(casesDir.getAutoModelingCrownsFolder(), f'{beforeDir}/crowns')
    shutil.move(casesDir.getProcessedModelCrownsFolder(), f'{afterDir}/crowns')
    shutil.move(casesDir.getTreatmentPlan(), f'{caseDirTmp}/Plan.json')

    shutil.rmtree(caseDir, ignore_errors=True)
    shutil.move(caseDirTmp, caseDir)


def processCase(caseId: str):
    casesDir = CasesDirWorker(caseId)

    # Convert Treatment plan ---> production movement results in STL
    create_files_for_standard_viewer_helper(casesDir)

    # Convert Treatment plan ---> production movement results in STL
    prepare_data(casesDir)
    # prepare_data_no_transform(casesDir);

    # Remove excess files and folders:
    casesDir.removeExcessFiles()

    # Copy manual-made models to new destination folder + rename them
    casesDir.copyProcessedModels()

    # Prepare config files:
    create_config_files(casesDir)
    create_processed_models_config_files(casesDir);

    sessionPath = f'~/Projects/data/cases_ml/{caseId}/automodeling/{caseId}_session.json'
    sessionPathProcessed = f'~/Projects/data/cases_ml/{caseId}/processed/{caseId}_session.json'
    handlers = ['processing_stable/preprocessing.py',
                'processing_stable/extract_features.py',
                'processing_stable/symmetry.py']

    params = f'-s {sessionPath}'
    return_code = 0
    for handler in handlers:
        cmd = f'python3 {handler} {params}'
        print(f'===================== {cmd} ========================')
        code = execute(cmd)
        if 0 != code:
            return_code = code

    params = f'-s {sessionPathProcessed}'
    for handler in handlers:
        cmd = f'python3 {handler} {params}'
        print(f'===================== {cmd} ========================')
        code = execute(cmd)
        if 0 != code:
            return_code = code

    CopyArtefactsAndClenup(casesDir)
    return return_code


# ======================================= Download case from S3 ===============================================

def getAchivedCasesDict() -> Dict:
    casesDict = dict()
    with open('data/archived.csv', newline='') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            casesDict[row[0]] = row[1]
    return casesDict;


def extract_all(archives, dst: str):
    with tarfile.open(archives, 'r:gz') as archive:
        archive.extractall(dst)


def getCaseFromS3(caseId: str,
                  caseUuid: str,
                  destFolder="/home/andtokm/Projects/data/cases_ml"):
    caseFolder = f"{destFolder}/{caseId}"
    destArchive = f"{caseFolder}.tar.gz"
    s3Command = f"s3cmd get s3://tam-archive/{caseUuid}.tar.gz {destArchive}"
    caseDataFolder = f"{caseFolder}/{caseUuid}"

    print(f"Downloading {caseUuid}.tar.gz file to {destArchive}")
    execute(s3Command)

    print(f"Extracting archive {destArchive} to {caseFolder}")
    extract_all(destArchive, caseFolder);

    print("Renaming folders....")
    shutil.move(caseDataFolder, f"{caseFolder}_data")
    os.remove(destArchive)
    os.rename(f"{caseFolder}_data", f"{caseFolder}")


# ========================= Store and restore processed cases to file ==================================

INFO_DELIMETER = '   '


def getProcessedCases() -> Set:
    processed_cases_file = '/home/andtokm/Projects/data/cases_ml/processedCases.txt'
    with open(processed_cases_file, 'r') as file:
        lines = set()
        for rawLine in file.readlines():
            line = rawLine.rstrip()
            space_pos = line.find(INFO_DELIMETER)
            if -1 == space_pos:
                caseId = line
            else:
                caseId = line[0: space_pos]
            lines.add(caseId)
        return set(lines)


def storeProcessedCase(caseId: str, info: str = None):
    processed_cases_file = '/home/andtokm/Projects/data/cases_ml/processedCases.txt'
    with open(processed_cases_file, 'a') as casesFile:
        casesFile.write(f'{caseId}')
        if None != info:
            casesFile.write(f'{INFO_DELIMETER}{info}')
        casesFile.write('\n')

# ======================================================================================================

''' Main '''
if __name__ == '__main__':
    processedCases = getProcessedCases()

    '''
    caseId = "10030"
    uuid = casesDict.get(caseId)
    getCaseFromS3(caseId, uuid)
    processCase(caseId)
    '''

    count = 0
    casesDict = getAchivedCasesDict();
    for caseId, caseUuid in casesDict.items():
        if caseId in processedCases:
            continue

        returnCode = 0;
        caseFolder = f"/home/andtokm/Projects/data/cases_ml/{caseId}"
        try:
            getCaseFromS3(caseId, caseUuid)
            returnCode = processCase(caseId)
            storeProcessedCase(caseId)
        except Exception as exc:
            print("============================== Exception raised ================================")
            print(exc)
            storeProcessedCase(caseId, str(exc))
            print("================================================================================")
            continue

        if 0 != returnCode:
            print(f"Return code = {returnCode}. Removing case folder {caseFolder}")
            shutil.rmtree(caseFolder, ignore_errors=True)

        count = count + 1;
        if count >= 15:
            break
