import argparse
import json
import logging.config
import os
import sys

from pathlib import Path
from typing import List, Dict

from vtkmodules.vtkCommonDataModel import vtkPolyData

from Automodeling.Utilities import Utilities
from Process import process
from utils.ToothOBJFileReader import ToothOBJFileReader

config = Path(os.path.realpath(__file__)).parent.absolute().joinpath("logging.conf")
# logging.config.fileConfig(fname=config,
#                           disable_existing_loggers=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--treatment_plan',
                        help='Treatment JSON file path', type=str, required=True)
    parser.add_argument('-o', '--crowns_obj_file',
                        help="Crowns .obj file path", type=str, required=True)
    parser.add_argument('-r', '--result_file',
                        help="Result JSON file path", type=str, required=False, default=None)
    options = parser.parse_args()

    crowns_file_path: str = options.crowns_obj_file
    treatment_plan: str = options.treatment_plan
    result_file: str = options.result_file

    logger = logging.getLogger("Logger")
    try:
        logger.debug(f'reading {crowns_file_path} file')
        reader = ToothOBJFileReader()
        reader.init_from_file(crowns_file_path)

        logger.debug(f'reading {treatment_plan} file')
        with open(treatment_plan) as jsonData:
            treatment_dict = json.loads(jsonData.read())
    except Exception as exc:
        logger.exception(exc)
        sys.exit(1)


    measurements: Dict = process(reader, treatment_dict)
    if result_file:
        with open(result_file, 'w') as json_file:
            json.dump(measurements, json_file)
    else:
        print(json.dumps(measurements))