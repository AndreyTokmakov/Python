from typing import Dict
from TreatmentQuality.methods.EstimationMethod import EstimationMethod
from vtkmodules.vtkCommonDataModel import vtkPolyData


class Bolton(EstimationMethod):
    """
    TODO: add description
    """

    def estimate(self,
                 teeth_data_map: Dict[int, vtkPolyData],
                 contact_points: Dict,
                 teeth_lengths: Dict) -> Dict:
        self.logger.debug(f'{__name__} entered')

        incisors_length_upper: float = \
            sum([teeth_lengths[tooth_id] for tooth_id in [13, 12, 11, 21, 22, 23]])

        incisors_length_lower: float = \
            sum([teeth_lengths[tooth_id] for tooth_id in [33, 32, 31, 41, 42, 43]])

        total_length_upper: float = \
            sum([teeth_lengths[tooth_id] for tooth_id in [16, 15, 14, 24, 25, 26]], incisors_length_upper)

        total_length_lower: float = \
            sum([teeth_lengths[tooth_id] for tooth_id in [36, 35, 34, 44, 45, 46]], incisors_length_lower)

        anterior_ratio = incisors_length_lower / incisors_length_upper * 100
        total_ratio = total_length_lower / total_length_upper * 100

        result = {
            'anterior_ratio': {'actual': anterior_ratio, 'expected': 77.2},
            'total_ratio': {'actual': total_ratio, 'expected': 91.3}
        }
        return result

    @property
    def name(self):
        return type(self).__name__.lower()