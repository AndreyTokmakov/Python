from typing import Dict, List

from TreatmentQuality.methods.EstimationMethod import EstimationMethod
from vtkmodules.vtkCommonDataModel import vtkPolyData
from TreatmentQuality.utils.UnorderedPair import UnorderedPair


class Pont(EstimationMethod):
    """
    TODO: add description
    """

    def estimate(self,
                 teeth_data_map: Dict[int, vtkPolyData],
                 contact_points: Dict,
                 teeth_lengths: Dict) -> Dict:
        self.logger.debug(f'{__name__} entered')

        incisors_length: float = self.get_incisors_length(teeth_lengths)
        premolar_distance_expected: float = incisors_length * 100 / 85
        molar_distance_expected: float = incisors_length * 100 / 65

        pt14, pt24 = teeth_data_map[14].GetCenter(), teeth_data_map[24].GetCenter()
        pt16, pt26 = teeth_data_map[16].GetCenter(), teeth_data_map[26].GetCenter()
        dist1Upper: float = Pont.distance_between_two_points(pt14, pt24)
        dist2Upper: float = Pont.distance_between_two_points(pt16, pt26)

        pt1Lower, pt2Lower = contact_points[UnorderedPair(34, 35)], contact_points[UnorderedPair(44, 45)]
        pt3Lower, pt4Lower = contact_points[UnorderedPair(36, 37)], contact_points[UnorderedPair(46, 47)]
        dist1Lower: float = Pont.distance_between_two_points(pt1Lower, pt2Lower)
        dist2Lower: float = Pont.distance_between_two_points(pt3Lower, pt4Lower)

        contactLower = contact_points[UnorderedPair(31, 41)]
        contactUpper = contact_points[UnorderedPair(11, 21)]

        result = {
            'upper': {
                'premolars': {'actual': dist1Upper, 'expected': premolar_distance_expected},
                'molars': {'actual': dist2Upper, 'expected': molar_distance_expected},
            },
            'lower': {
                'premolars': {'actual': dist1Lower, 'expected': premolar_distance_expected},
                'molars': {'actual': dist2Lower, 'expected': molar_distance_expected},
            },
            'points': {
                'upper': {'premolar_right': pt14, 'premolar_left': pt24,
                          'molar_right': pt16, 'molar_left': pt26,
                          'center': contactUpper},
                'lower': {'premolar_left': pt1Lower, 'premolar_right': pt2Lower,
                          'molar_left': pt3Lower, 'molar_right': pt4Lower,
                          'center': contactLower}
            }
        }
        return result

    @property
    def name(self):
        return type(self).__name__.lower()