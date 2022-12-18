import json
import multiprocessing
import threading
from concurrent.futures import ThreadPoolExecutor

import time
import datetime

import math
import numpy as np
from typing import List, Dict, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonMath import vtkMatrix4x4
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersGeneral import vtkIntersectionPolyDataFilter
from vtkmodules.vtkRenderingCore import vtkActor

from TreatmentQuality.methods.Bolton import Bolton
from TreatmentQuality.methods.Korkhaus import Korkhaus
from TreatmentQuality.methods.Ponth import Pont
from TreatmentQuality.utils.ToothOBJFileReader import ToothOBJWorker
from TreatmentQuality.utils.UnorderedPair import UnorderedPair
from TreatmentQuality.utils.Utilities import Utilities

'''
class Tests(object):
    UPPER_TEETH = {18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28}
    LOWER_TEETH = {48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38}
    LEFT_TEETH = {48, 47, 46, 45, 44, 43, 42, 41, 11, 12, 13, 14, 15, 16, 17, 18}
    RIGHT_TEETH = {21, 22, 23, 24, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 38}

    # TODO: Build it manually - do not use VTK
    # TODO: Research for existing solutions
    @staticmethod
    def buildRotationMatrixBad(xAngle: float,
                               yAngle: float,
                               zAngle: float) -> vtkMatrix4x4:
        transform: vtkTransform = vtkTransform()
        transform.RotateX(xAngle)
        transform.RotateY(yAngle)
        transform.RotateZ(zAngle)

        matrix: vtkMatrix4x4 = vtkMatrix4x4()
        transform.GetMatrix(matrix)
        return matrix

    # TODO: Check is there is some more better way to do it
    @staticmethod
    def vtkMatrixToNumpy(mat: vtkMatrix4x4) -> np.ndarray:
        temp = [0] * 16
        mat.DeepCopy(temp, mat)
        mat = np.array(temp).reshape(4, 4)
        mat = np.delete(np.asarray(mat), np.s_[3], axis=0)
        return np.delete(mat, np.s_[3], axis=1)

    @staticmethod
    def angle_between_vectors(vect1: np.ndarray, vect2: np.ndarray):
        a = np.dot(vect1, vect2)
        b = np.sqrt(np.dot(vect1, vect1)) * np.sqrt(np.dot(vect2, vect2))
        return math.acos(a / b) * 180 / math.pi

    @staticmethod
    def get_orientation_angles(angulation_axis: np.ndarray,
                               symmetry_axis: np.ndarray):
        sign = symmetry_axis[1] / abs(symmetry_axis[1])  # HACK: get Y coordinate sign
        point_vertical = np.asarray([0, sign * 1, 0])
        point_horizontal = np.asarray([1, 0, 0])

        axisPoint, ptTooth = point_vertical, symmetry_axis * np.asarray([0, 1, 1])
        xRotateAngle = Tests.angle_between_vectors(axisPoint, ptTooth)
        xRotateAngle *= -1 if axisPoint[1] > ptTooth[1] else 1

        axisPoint, ptTooth = point_horizontal, angulation_axis * np.asarray([1, 0, 1])
        yRotateAngle = Tests.angle_between_vectors(axisPoint, ptTooth)
        yRotateAngle *= -1 if axisPoint[2] > ptTooth[2] else 1

        axisPoint, ptTooth = point_horizontal, angulation_axis * np.asarray([1, 1, 0])
        zRotateAngle = Tests.angle_between_vectors(axisPoint, ptTooth)
        zRotateAngle *= -1 if ptTooth[1] > axisPoint[1] else 1

        return xRotateAngle, yRotateAngle, zRotateAngle

    @staticmethod
    def orient_single_tooth_treatment_plan(id_mesh_dict: Dict[int, vtkPolyData],
                                           treatmentJson: Dict,
                                           toothId: int) -> vtkPolyData:
        toothPolyData: vtkPolyData = id_mesh_dict[toothId]
        axes: np.ndarray = np.asarray(treatmentJson['modellingData'][str(toothId)]['axes'])

        # Rotate axis to fit the current jaws orientation:
        matrix = Tests.buildRotationMatrixBad(90, 180, 0)
        matrix = Tests.vtkMatrixToNumpy(matrix)

        angulation_axis, symmetry_axis = axes[0:3], axes[6:9]
        angulation_axis = np.matmul(angulation_axis, matrix)
        symmetry_axis = np.matmul(symmetry_axis, matrix)

        xRotateAngle, yRotateAngle, zRotateAngle = Tests.get_orientation_angles(angulation_axis, symmetry_axis)
        if toothId in Tests.LOWER_TEETH:
            yRotateAngle = yRotateAngle - 180
            zRotateAngle = zRotateAngle - 180

        return Utilities.rotatePolyData(toothPolyData, xRotateAngle, yRotateAngle, zRotateAngle)
'''


class Worker(object):
    UPPER_TEETH = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28]
    LOWER_TEETH = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38]
    ALL_TEETH = list(LOWER_TEETH + UPPER_TEETH)

    def __init__(self):
        # Prepare matrix to reorient axis (since the tooth mesh was rotated on {90, 180, 0} already)
        self.__matrix = Utilities.buildRotation_matrix_bad(90, 180, 0)
        self.__matrix = Utilities.vtkMatrixToNumpy(self.__matrix)

    @staticmethod
    def __get_teeth_contact_point(tooth1: vtkPolyData,
                                  tooth2: vtkPolyData) -> Tuple:
        # Get centers:
        pt1: np.ndarray = np.asarray(tooth1.GetCenter())
        pt2: np.ndarray = np.asarray(tooth2.GetCenter())

        # Calc line equation in the slope/intercept form
        slopeY, interceptY = Utilities.get_line_coefficients(pt1[0:2], pt2[0:2])  # x, y
        slopeZ, interceptZ = Utilities.get_line_coefficients(pt1[0:3:2], pt2[0:3:2])  # x, z
        x1, x2 = pt1[0], pt2[0]
        xMid = x2 - (x2 - x1) / 2

        num_steps = 50
        booleanFilter = vtkIntersectionPolyDataFilter()
        booleanFilter.GlobalWarningDisplayOff()

        # Move the teeth towards each other until the first intersection
        for x in np.arange(x1, xMid, (xMid - x1)/num_steps):
            booleanFilter.SetInputData(0, tooth1)
            booleanFilter.SetInputData(1, tooth2)
            booleanFilter.Update()
            if booleanFilter.GetNumberOfIntersectionPoints() > 0:
                break

            x_pos1, x_pos2 = (x, x2 + x1 - x)
            y_pos1, y_pos2 = (x_pos1 * slopeY + interceptY, x_pos2 * slopeY + interceptY)
            z_pos1, z_pos2 = (x_pos1 * slopeZ + interceptZ, x_pos2 * slopeZ + interceptZ)

            tooth1 = Utilities.setPolyDataCenter(tooth1, x_pos1, y_pos1, z_pos1)
            tooth2 = Utilities.setPolyDataCenter(tooth2, x_pos2, y_pos2, z_pos2)

        if booleanFilter.GetNumberOfIntersectionPoints() > 0:
            return booleanFilter.GetOutput().GetCenter()
        else:
            return None

    @staticmethod
    def __get_orientation_angles(angulation_axis: np.ndarray,
                                 symmetry_axis: np.ndarray) -> Tuple[float, float, float]:
        sign = symmetry_axis[1] / abs(symmetry_axis[1])  # HACK: get Y coordinate sign
        point_vertical = np.asarray([0, sign * 1, 0])
        point_horizontal = np.asarray([1, 0, 0])

        axisPoint, ptTooth = point_vertical, symmetry_axis * np.asarray([0, 1, 1])
        xRotateAngle = Utilities.angle_between_vectors(axisPoint, ptTooth)
        xRotateAngle *= -1 if axisPoint[1] > ptTooth[1] else 1

        axisPoint, ptTooth = point_horizontal, angulation_axis * np.asarray([1, 0, 1])
        yRotateAngle = Utilities.angle_between_vectors(axisPoint, ptTooth)
        yRotateAngle *= -1 if axisPoint[2] > ptTooth[2] else 1

        axisPoint, ptTooth = point_horizontal, angulation_axis * np.asarray([1, 1, 0])
        zRotateAngle = Utilities.angle_between_vectors(axisPoint, ptTooth)
        zRotateAngle *= -1 if ptTooth[1] > axisPoint[1] else 1

        return xRotateAngle, yRotateAngle, zRotateAngle

    def __orient_single_tooth(self,
                              id_mesh_dict: Dict[int, vtkPolyData],
                              treatment_json: Dict,
                              tooth_id: int) -> vtkPolyData:
        toothPolyData: vtkPolyData = id_mesh_dict[tooth_id]
        axes: np.ndarray = np.asarray(treatment_json['modellingData'][str(tooth_id)]['axes'])

        angulation_axis, symmetry_axis = axes[0:3], axes[6:9]
        angulation_axis = np.matmul(angulation_axis, self.__matrix)
        symmetry_axis = np.matmul(symmetry_axis, self.__matrix)

        xRotateAngle, yRotateAngle, zRotateAngle = Worker.__get_orientation_angles(angulation_axis, symmetry_axis)
        if tooth_id in Worker.LOWER_TEETH:
            yRotateAngle, zRotateAngle = yRotateAngle - 180, zRotateAngle - 180

        return Utilities.rotatePolyData(toothPolyData, xRotateAngle, yRotateAngle, zRotateAngle)

    def __get_teeth_lengths(self,
                            id_mesh_dict: Dict[int, vtkPolyData],
                            treatment_dict: Dict) -> Dict[int, float]:
        teeth_lengths: Dict[int, float] = dict()
        for toothId, toothData in id_mesh_dict.items():
            toothData = self.__orient_single_tooth(id_mesh_dict, treatment_dict, toothId)
            bounds: np.array = np.asarray(toothData.GetBounds())
            teeth_lengths[toothId] = bounds[1] - bounds[0]
            # TODO: Remove me. Just for DEBUG
            # if toothId in [11, 12, 21, 22]:
            #    Utilities.visualize(toothData)
        return teeth_lengths

    def __get_contact_points(self,
                             id_mesh_dict: Dict[int, vtkPolyData]) -> Dict[UnorderedPair, Tuple[float, float, float]]:
        points_dict: Dict[UnorderedPair, Tuple[float, float, float]] = dict()
        for teeth in [self.LOWER_TEETH, self.UPPER_TEETH]:
            for index in range(1, len(teeth)):
                id1, id2 = teeth[index - 1], teeth[index]
                if id1 in id_mesh_dict.keys() and id2 in id_mesh_dict.keys():
                    tooth1, tooth2 = id_mesh_dict[id1], id_mesh_dict[id2]
                    points_dict[UnorderedPair(id1, id2)] = Worker.__get_teeth_contact_point(tooth1, tooth2)
        return points_dict

    def __get_contact_points_fast(self,
                                  id_mesh_dict: Dict[int, vtkPolyData]) -> Dict[UnorderedPair, Tuple[float, float, float]]:
        # Prepare tooth pairs for processing in multithreaded mode:
        teeth_list_pairs = []
        for teeth in [self.LOWER_TEETH, self.UPPER_TEETH]:
            teeth_list_pairs.extend([(teeth[index - 1], teeth[index]) for index in range(1, len(teeth))])

        def split_to_N_parts(a: List[Tuple], n) -> List[List]:
            k, m = divmod(len(a), n)
            return list(a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

        process_count = int(multiprocessing.cpu_count() / 2)
        teeth_list_pairs = split_to_N_parts(teeth_list_pairs, process_count)

        # Handler: Calculate contact points for each given tooth pair, and then put results to the queue
        def handler(pairs: List[Tuple[int, int]],
                    bus_queue: multiprocessing.Queue):
            for id1, id2 in pairs:
                if id1 in id_mesh_dict.keys() and id2 in id_mesh_dict.keys():
                    tooth1, tooth2 = id_mesh_dict[id1], id_mesh_dict[id2]
                    bus_queue.put((UnorderedPair(id1, id2), Worker.__get_teeth_contact_point(tooth1, tooth2)))

        # Run processes and push them into the 'workers' list:
        workers = []
        queue = multiprocessing.Queue()
        for i in range(process_count):
            proc = multiprocessing.Process(target=handler, args=(teeth_list_pairs[i], queue))
            workers.append(proc)
            proc.start()

        # Wait for all processes to finish:
        for proc in workers:
            proc.join()

        # Get results stored in the queue and add them to the 'contact_points' dictionary:
        contact_points: Dict[UnorderedPair, Tuple[float, float, float]] = dict()
        while not queue.empty():
            ids_pair, point = queue.get()
            contact_points[ids_pair] = point

        return contact_points

    def process_crowns(self,
                       objWorker: ToothOBJWorker,
                       treatment_dict: str):
        teeth_lengths = self.__get_teeth_lengths(objWorker.teethMapOriented, treatment_dict)
        # contact_points = self.__get_contact_points(objWorker.teethMap)
        contact_points = self.__get_contact_points_fast(objWorker.teethMap)
        return teeth_lengths, contact_points


# TODO: Add class to calc each tooth width
# TODO: Add class to calc teeth contact points
# TODO: EstimationMethod should not work with VTK-DATA itself??
#       Only with centers, tooth-widths and contact points??

def Test1(crowns_file_path: str,
          treatment_json: str):
    start_time = time.time()

    worker = ToothOBJWorker(crowns_file_path)

    end_time = time.time()
    print(f'Phase1: {end_time - start_time}')
    start_time = end_time

    with open(treatment_json) as jsonData:
        treatmentJson = json.loads(jsonData.read())

    end_time = time.time()
    print(f'Phase2: {end_time - start_time}')
    start_time = end_time

    teethMap: Dict[int, vtkPolyData] = worker.teethMap
    lowerIds = [36, 35, 34, 33, 32, 31, 41, 42, 43, 44, 45, 46]

    worker = Worker()
    for toothId in Worker.UPPER_TEETH.union(Worker.LOWER_TEETH):
        toothData = worker.orient_single_tooth_treatment_plan(teethMap, treatmentJson, toothId)
        bounds: np.array = np.asarray(toothData.GetBounds())
        xLength: float = bounds[1] - bounds[0]

        print(f'Id: {toothId}, len: {xLength}')

        # ptCenter: np.array = np.asarray(toothData.GetCenter())
        # xLeftPoint: np.array = ptCenter - np.array([xLength / 2, 0, 0])
        # xRightPoint: np.array = ptCenter + np.array([xLength / 2, 0, 0])
        # pts1: vtkActor = Utilities.getPointsActor([xLeftPoint, xRightPoint], color=[1, 0, 0])
        # dataActor = Utilities.getPolyDataActor(toothData)
        # outlineActor = Utilities.getOutlineActor(toothData)
        # Utilities.DisplayActors([dataActor,  pts1], position=(350, 50))

    # methods[0].estimate(worker.teethMap, treatmentJson)
    end_time = time.time()
    print(f'Phase3: {end_time - start_time}')
    start_time = end_time


def ProcessCrownsTests(crowns_file_path: str,
                       treatment_json: str):
    objWorker = ToothOBJWorker(SRC_MODEL_OBJ)
    with open(TREATMENT_PLAN) as jsonData:
        treatment_dict = json.loads(jsonData.read())

    worker = Worker()
    teeth_lengths, contact_points = worker.process_crowns(objWorker, treatment_dict)

    Korkhaus().estimate(objWorker.teethMap, contact_points, teeth_lengths)
    Pont().estimate(objWorker.teethMap, contact_points, teeth_lengths)
    Bolton().estimate(objWorker.teethMap, contact_points, teeth_lengths)


def GetContactPoint_Performance(crowns_file_path: str,
                                treatment_json: str):
    UPPER_TEETH = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28]
    LOWER_TEETH = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38]

    objWorker = ToothOBJWorker(crowns_file_path)
    id_mesh_dict: Dict[int, vtkPolyData] = objWorker.teethMap
    with open(treatment_json) as jsonData:
        treatment_dict = json.loads(jsonData.read())

    '''
    # ----------------- Multithreading ---------------------
    def thread_function(pairs: List[Tuple[int, int]]):
        print(f'Started: {threading.get_ident()}')
        for id1, id2 in pairs:
            if id1 in id_mesh_dict.keys() and id2 in id_mesh_dict.keys():
                tooth1, tooth2 = id_mesh_dict[id1], id_mesh_dict[id2]
                MoveUtils.GetTeethContactPoint(tooth1, tooth2)
        # print(f'Done: {threading.get_ident()}')

    start_time = time.time()
    for i in range(1):
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(thread_function, teeth_list_pairs)
    print(f'Execution time: {time.time() - start_time}')
    '''

    '''
    id_mesh_dict: Dict[int, vtkPolyData] = objWorker.teethMap
    start_time = time.time()

    contact_points: Dict[UnorderedPair, Tuple[float, float, float]] = dict()
    for teeth in [LOWER_TEETH, UPPER_TEETH]:
        for index in range(1, len(teeth)):
            id1, id2 = teeth[index - 1], teeth[index]
            if id1 in id_mesh_dict.keys() and id2 in id_mesh_dict.keys():
                tooth1, tooth2 = id_mesh_dict[id1], id_mesh_dict[id2]
                contact_points[UnorderedPair(id1, id2)] = MoveUtils.GetTeethContactPoint(tooth1, tooth2)
    print(f'Execution time: {time.time() - start_time}')
    
    '''

    actors: List[vtkActor] = []
    worker = Worker()

    start_time = time.time()
    teeth_lengths, contact_points = worker.process_crowns(objWorker, treatment_dict)
    print(f'Execution time: {time.time() - start_time}')



    ##################################### Visualization ##########################################

    upperTeeth: List[vtkPolyData] = [data for _id, data in objWorker.teethMap.items() if _id in Worker.UPPER_TEETH]
    lowerTeeth: List[vtkPolyData] = [data for _id, data in objWorker.teethMap.items() if _id in Worker.LOWER_TEETH]
    polyDataUpper: vtkPolyData = Utilities.appendPolyData(upperTeeth)
    polyDataLower: vtkPolyData = Utilities.appendPolyData(lowerTeeth)

    ptsActorUpper: vtkActor = \
        Utilities.getPointsActor([pt for ids, pt in contact_points.items() if ids.a in Worker.UPPER_TEETH])
    ptsActorLower: vtkActor = \
        Utilities.getPointsActor([pt for ids, pt in contact_points.items() if ids.a in Worker.LOWER_TEETH])

    actors.append(ptsActorUpper)
    actors.append(ptsActorLower)
    actors.append(Utilities.getPolyDataActor(polyDataUpper))
    actors.append(Utilities.getPolyDataActor(polyDataLower))
    Utilities.DisplayActors(actors)


if __name__ == '__main__':
    # CASE_ID = '2630'
    # CASE_ID = '2280'
    # CASE_ID = '2416'
    # CASE_ID = '2425'
    CASE_ID = '2449'

    CASE_DIR = f'/home/andtokm/Projects/data/cases/{CASE_ID}'
    MODELS_DIR = f'{CASE_DIR}/models'
    SRC_MODEL_OBJ = f'{MODELS_DIR}/crowns.obj'
    TREATMENT_PLAN = f'{CASE_DIR}/Plan.json'

    # Test1(SRC_MODEL_OBJ, TREATMENT_PLAN)
    # ProcessCrownsTests(SRC_MODEL_OBJ, TREATMENT_PLAN)
    GetContactPoint_Performance(SRC_MODEL_OBJ, TREATMENT_PLAN)

    '''
    def getMatrix(xAngle: float,
                  yAngle: float,
                  zAngle: float) -> vtkMatrix4x4:
        transform: vtkTransform = vtkTransform()
        transform.RotateX(xAngle)
        transform.RotateY(yAngle)
        transform.RotateZ(zAngle)

        matrix: vtkMatrix4x4 = vtkMatrix4x4()
        transform.GetMatrix(matrix)
        return matrix

    def vtkMatrixToNumpy1(mat: vtkMatrix4x4) -> np.ndarray:
        temp = [0] * 16
        mat.DeepCopy(temp, mat)
        mat = np.array(temp).reshape(4, 4)
        mat = np.delete(np.asarray(mat), np.s_[3], axis=0)
        return np.delete(mat, np.s_[3], axis=1)

    def vtkMatrixToNumpy2(mat: vtkMatrix4x4) -> np.ndarray:
        tmp = np.zeros(16, float)
        mat.DeepCopy(tmp, mat)
        mat = np.array(tmp).reshape(4, 4)
        mat = np.delete(np.asarray(mat), np.s_[3], axis=0)
        return np.delete(mat, np.s_[3], axis=1)

    M = getMatrix(90, 0, 0)

    #print(vtkMatrixToNumpy1(m))
    # print(vtkMatrixToNumpy2(m))

    #temp = np.eye(4, dtype=float)
    #print(temp)
    #print(temp.getA())

    mat = np.ones([4, 4])
    # mat = np.zeros(16, float)

    # tmp = np.zeros(16, float)
    # M.DeepCopy(mat.data, M)

    #at.tolist()[0][0] = 22

    '''