
import logging

from typing import List, Dict
from methods.EstimationMethod import EstimationMethod
from methods.Bolton import Bolton
from methods.Korkhaus import Korkhaus
from methods.Ponth import Pont
from utils.ToothOBJFileReader import ToothOBJFileReader
from utils.Worker import Worker

logger = logging.getLogger("Logger")


def process(reader: ToothOBJFileReader,
            treatment_plan: Dict) -> Dict:
    worker = Worker()
    teeth_lengths, contact_points = worker.process_crowns(reader, treatment_plan)

    data = dict()
    estimators: List[EstimationMethod] = [Korkhaus(),
                                          Pont(),
                                          Bolton()]
    for method in estimators:
        try:
            result = method.estimate(reader.teethMap, contact_points, teeth_lengths)
            data[method.name] = result
        except Exception as exc:
            logger.exception(exc)

    # HACK: Move Pont points to the upper level of the dictionary:
    pont_data = data.get("pont", None)
    if pont_data:
        data['points'] = pont_data.pop('points')

    data['widths'] = teeth_lengths
    return data