from typing import Dict, List, Tuple

from vtkmodules.vtkCommonDataModel import vtkLine, vtkPolyData
from TreatmentQuality.methods.EstimationMethod import EstimationMethod
from TreatmentQuality.utils.UnorderedPair import UnorderedPair
from TreatmentQuality.utils.Utilities import Utilities


# TODO: Add class description
class Korkhaus(EstimationMethod):
    '''
    The Korkhaus method allows you to determine the ideal length
    from the line connecting the first premolars to the point of contact of the anterior incisors
    based on the sum of the lengths of the UPPER 4 anterior incisors.
    This ideal length for the upper and lower jaws differ by exactly 2 units: [upper_dist = lower_dist + 2]
    '''

    VALUES_TABLE = [
        (26.5, 15.8),  # 13.8 for lower
        (27.0, 16.0),  # 14.0 for lower
        (27.5, 16.3),  # 14.3 for lower
        (28.0, 16.5),  # and so on ......
        (28.5, 16.8),
        (29.0, 17.0),
        (29.5, 17.3),
        (30.0, 17.5),
        (30.5, 17.8),
        (31.0, 18.0),
        (31.5, 18.3),
        (32.0, 18.5),
        (32.5, 18.8),
        (33.0, 19.0),
        (33.5, 19.3),
        (34.0, 19.5),
        (34.5, 19.8),
        (35.0, 20.0),
        (35.5, 20.5),
        (36.0, 21.0),
        (36.5, 21.5)
    ]

    UPPER_TO_LOWER_DIFF: float = 2.0

    def get_distance(self,
                     incisors_length: float) -> float:
        table = self.VALUES_TABLE
        # if input value LESS than fist value, return corresponding value
        if incisors_length <= table[0][0]:
            return table[0][1]
        # if input value GREATER than last value, return its corresponding value
        elif incisors_length >= table[-1][0]:
            return table[-1][1]

        # Determine bounds of the input length value:
        lower_bound, upper_bound = table[0], table[-1]
        for i in range(1, len(table)):
            if table[i][0] >= incisors_length:
                lower_bound, upper_bound = table[i - 1], table[i]
                break

        ratio: float = (incisors_length - lower_bound[0]) / (upper_bound[0] - lower_bound[0])
        offset: float = (upper_bound[1] - lower_bound[1]) * ratio
        return lower_bound[1] + offset

    def getDistanceUpper(self, incisors_length: float) -> float:
        return self.get_distance(incisors_length)

    def getDistanceLower(self, incisors_length: float) -> float:
        return self.get_distance(incisors_length) - self.UPPER_TO_LOWER_DIFF

    """
    TODO: add description
    """
    def estimate(self,
                 teeth_data_map: Dict[int, vtkPolyData],
                 contact_points: Dict,
                 teeth_lengths: Dict) -> Dict:
        self.logger.debug(f'{__name__} entered')

        incisors_length: float = self.get_incisors_length(teeth_lengths)
        self.logger.debug(f'Incisors length = {incisors_length}')

        pt1Upper, pt2Upper = teeth_data_map[14].GetCenter(), teeth_data_map[24].GetCenter()
        contactUpper = contact_points[UnorderedPair(11, 21)]
        distUpper, closestUpper = Utilities.distance_to_line(contactUpper, pt1Upper, pt2Upper)

        pt1Lower, pt2Lower = contact_points[UnorderedPair(34, 35)], contact_points[UnorderedPair(44, 45)]
        contactLower = contact_points[UnorderedPair(31, 41)]
        distLower, closestLower = Utilities.distance_to_line(contactLower, pt1Lower, pt2Lower)

        upper_expected = self.getDistanceUpper(incisors_length)
        lower_expected = self.getDistanceLower(incisors_length)

        self.logger.debug(f'Expected Korkhaus length upper: {upper_expected}, lower: {lower_expected}')
        self.logger.debug(f'Actual upper length: {distUpper}')
        self.logger.debug(f'Actual lower length: {distLower}')

        return {
            'upper': {'actual': distUpper, 'expected': upper_expected},
            'lower': {'actual': distLower, 'expected': lower_expected}
        }

    @property
    def name(self):
        return type(self).__name__.lower()