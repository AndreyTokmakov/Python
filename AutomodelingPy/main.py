import json
import math

import numpy as np

from typing import Dict, List
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkRenderingCore import vtkActor

from AutomodelingPy.alignment.AngulationAligner import AngulationAligner
from AutomodelingPy.alignment.EstimateCurve import EstimateCurve
from AutomodelingPy.alignment.ExtrusionAligner import ExtrusionAligner
from AutomodelingPy.alignment.Occlusion import Occlusion
from AutomodelingPy.alignment.TorkAligner import TorkAligner
from AutomodelingPy.estimation.DistanceEstimator import DistanceEstimator
from AutomodelingPy.estimation.Estimator import Estimator
from AutomodelingPy.geometry.Line2D import Line2D
from AutomodelingPy.geometry.Point2D import Point2D
from AutomodelingPy.model.FDI import FDI
from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Reader import Reader
from AutomodelingPy.utils.Transformation import TransformationData
from AutomodelingPy.utils.Utilities import Utilities

# Treatment plan (JSON) parameter names:
MODELING_DATA_PARAM_NAME = 'modellingData'
AXES_PARAM_NAME = 'axes'
ORIGIN_PARAM_NAME = 'origin'

crowns_obj_file: str = './data/Crowns.obj'
treatment_plan: str = './data/Plan.json'

class Utils(object):

    @staticmethod
    def read_teeth(obj_file: str, plan_file: str) -> Dict[int, Tooth]:
        reader = Reader()
        reader.init_from_file(obj_file)

        with open(plan_file) as jsonData:
            plan = json.loads(jsonData.read())

        x_angle, y_angle = 90, 180

        matrix = Utilities.buildRotation_matrix_bad(x_angle, y_angle, 0)
        matrix = Utilities.vtkMatrixToNumpy(matrix)

        estimator: Estimator = DistanceEstimator()
        teeth: Dict[int, Tooth] = {}
        for tooth_id, tooth_data in reader.teethMap.items():
            axes: np.ndarray = np.asarray(plan[MODELING_DATA_PARAM_NAME][str(tooth_id)][AXES_PARAM_NAME])
            tooth: Tooth = Tooth(tooth_id, Utilities.rotatePolyData(tooth_data, x_angle, y_angle),
                                 axes[0:3], axes[3:6], axes[6:9])

            tooth.xAxis = np.matmul(tooth.xAxis, matrix)
            tooth.yAxis = np.matmul(tooth.yAxis, matrix)
            tooth.zAxis = np.matmul(tooth.zAxis, matrix)

            estimator.estimate(tooth)
            teeth[tooth_id] = tooth

        return teeth

    @staticmethod
    def display_lower_teeth(teeth: Dict[int, Tooth],
                            windowName: str = "VTK Window",
                            xAngle: float = 90,
                            yAngle: float = 0,
                            zAngle: float = 0):
        lower_teeth = [pd for tooth_id, pd in teeth.items() if tooth_id in Utilities.LOWER_TEETH]
        actors: List[vtkActor] = []
        for tooth in lower_teeth:
            actor = Utilities.getPolyDataActor(tooth.data)
            actor.RotateX(xAngle)
            actor.RotateY(yAngle)
            actor.RotateZ(zAngle)
            actors.append(actor)
        Utilities.DisplayActors(actors, windowName=windowName)

########################################################################################


def EstimateTeethTest():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)

    for k, tooth in teeth.items():
        print(f'{k} --> {tooth.width}')


def Test_Visualize():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    Utils.display_lower_teeth(teeth)


def Occlusion_Plane_Test():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    obj: Occlusion = Occlusion()
    transformation: TransformationData = TransformationData()

    '''for tooth_id in TorkAligner.LOWER_TEETH:
        tooth: Tooth = teeth.get(tooth_id)
        print(f'--------------------------------- {tooth_id} ---------------------------- ')
        print(tooth.zAxis)'''

    angles = obj.orient_teeth(teeth, transformation)
    print(angles)


    '''print(f'AFTER: ---------------------------{angles}--------------------------')
    for tooth_id in TorkAligner.LOWER_TEETH:
        tooth: Tooth = teeth.get(tooth_id)
        print(f'--------------------------------- {tooth_id} ---------------------------- ')
        print(tooth.zAxis)'''


def AngulationAligner_Test():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    angulation: AngulationAligner = AngulationAligner()
    occlusion: Occlusion = Occlusion()

    transformation: TransformationData = TransformationData()
    occlusion.orient_teeth(teeth, transformation)

    # Utils.display_lower_teeth(teeth, 'Original', xAngle=0, yAngle=0)

    angulation.align(teeth, transformation)

    # Utils.display_lower_teeth(teeth, 'Aligned', xAngle=0, yAngle=0)

    '''print('--------------------------------------------------------')
    for tooth_id, transform in transformation.teethTransform.items():
        print(f'{tooth_id} {transform.angulationMatrix}')'''


def TorksAligner_Test():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    occlusion: Occlusion = Occlusion()
    torks: TorkAligner = TorkAligner()
    transformation: TransformationData = TransformationData()

    # occlusion.orient_teeth(teeth)
    Utils.display_lower_teeth(teeth, 'Original')
    torks.align(teeth, transformation)
    Utils.display_lower_teeth(teeth, 'Aligned')

    '''print('--------------------------------------------------------')
    for tooth_id, transform in transformation.teethTransform.items():
        print(f'{tooth_id} {transform.torksMatrix}')'''


def ExtrusionAligner_Test():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    occlusion: Occlusion = Occlusion()
    extrusion: ExtrusionAligner = ExtrusionAligner()
    transformation: TransformationData = TransformationData()

    occlusion.orient_teeth(teeth, transformation)

    Utils.display_lower_teeth(teeth, 'Original', xAngle=0)

    extrusion.align(teeth, transformation)

    Utils.display_lower_teeth(teeth, 'Aligned', xAngle=0)


def TestAll():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)

    occlusion: Occlusion = Occlusion()
    torks: TorkAligner = TorkAligner()
    angulation: AngulationAligner = AngulationAligner()
    transformation: TransformationData = TransformationData()

    occlusion.orient_teeth(teeth, transformation)

    Utils.display_lower_teeth(teeth, 'Original')

    angulation.align(teeth, transformation)
    torks.align(teeth, transformation)

    Utils.display_lower_teeth(teeth, 'Aligned')


def vis_axes():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    '''
    actors: List[vtkActor] = []
    for tooth_id, tooth in teeth.items():
        if FDI.isLowerTooth(tooth_id):
            continue

        horizontal, symmetry, vertical = tooth.xAxis, tooth.yAxis, tooth.zAxis
        origin = tooth.getCenter()

        mult: float = 7.0  # Just to make axed lines longer than normal (1.0) size
        symmetryAxisPt1, symmetryAxisPt2 = origin - symmetry * mult, origin + symmetry * mult
        horizontalAxisPt1, horizontalAxisPt2 = origin - horizontal * mult, origin + horizontal * mult
        verticalPt1, verticalPt2 = origin - vertical * mult, origin + vertical * mult

        # Add axes-like (3D lines) actors to list
        actors.append(Utilities.getLineActor(verticalPt1, verticalPt2, color=[1, 0, 0]))
        actors.append(Utilities.getLineActor(symmetryAxisPt1, symmetryAxisPt2, color=[0, 1, 0]))
        actors.append(Utilities.getLineActor(horizontalAxisPt1, horizontalAxisPt2, color=[0, 0, 1]))
        actors.append(Utilities.getPolyDataActor(tooth.data))

        # Visualize/Display actors:
    Utilities.DisplayActors(actors, position=(50, 100))
    '''

    for _, tooth in teeth.items():
        Utilities.DisplayToothWithAxes(tooth)


def EstimateCurveTest():
    teeth: Dict[int, Tooth] = Utils.read_teeth(crowns_obj_file, treatment_plan)
    curve: EstimateCurve = EstimateCurve()

    occlusion: Occlusion = Occlusion()
    torks: TorkAligner = TorkAligner()
    angulation: AngulationAligner = AngulationAligner()

    # Utils.display_lower_teeth(teeth, 'Original')
    transformation: TransformationData = TransformationData()

    occlusion.orient_teeth(teeth, transformation)
    angulation.align(teeth, transformation)
    torks.align(teeth, transformation)

    curve.estimate(teeth, transformation)

    # Utils.display_lower_teeth(teeth, 'Aligned')


if __name__ == '__main__':
    # vis_axes()
    # Test_Visualize()
    # EstimateTeethTest()
    # Occlusion_Plane_Test()
    # AngulationAligner_Test()
    # TorksAligner_Test()
    # ExtrusionAligner_Test()
    # TestAll()

    EstimateCurveTest()
