import logging
import logging.config
import multiprocessing

import math
import numpy as np
from typing import List, Dict, Tuple
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkFiltersGeneral import vtkIntersectionPolyDataFilter

from TreatmentQuality.utils.ToothOBJFileReader import ToothOBJFileReader
from TreatmentQuality.utils.UnorderedPair import UnorderedPair
from TreatmentQuality.utils.Utilities import Utilities


class Worker(object):
    UPPER_TEETH = [18, 17, 16, 15, 14, 13, 12, 11, 21, 22, 23, 24, 25, 26, 27, 28]
    LOWER_TEETH = [48, 47, 46, 45, 44, 43, 42, 41, 31, 32, 33, 34, 35, 36, 37, 38]
    ALL_TEETH = list(LOWER_TEETH + UPPER_TEETH)

    def __init__(self):
        # Prepare matrix to reorient axis (since the tooth mesh was rotated on {90, 180, 0} already)

        # Get the logger specified in the file
        # logging.config.fileConfig(fname='logging.conf', disable_existing_loggers=False)
        self.logger = logging.getLogger("Logger")

        self.__matrix = Utilities.buildRotation_matrix_bad(90, 180, 0)
        self.__matrix = Utilities.vtkMatrixToNumpy(self.__matrix)

    '''
    The method calculates the contact points of two teeth (or two other objects of the vtkPolyData type).
    The method also calculates the estimated contact point of two teeth even if they do not have a
    real intersection of objects.

    The algorithm of the method:
    1. Get centroids of teeth
    2. Obtain the equation of a straight line connecting the centroids
    3. Check whether the teeth intersect in this (initial) position.
    4. If there is no intersection of the volumes of the teeth, we begin to move the teeth in
       small steps towards each other along the line connecting their centroids
    5. At each such step, we check the intersection of the teeth, and if there are any, we stop the loop
    6. As a point of contact, we return the centroid of the object that is the intersection of
       two teeth in the current position
    '''
    @staticmethod
    def get_teeth_contact_point(tooth1: vtkPolyData,
                                tooth2: vtkPolyData,
                                id1: int, id2: int) -> Tuple:
        if 12 == id1 and 11 == id2:
            print(f"Processing({id1}, {id2})")
            Utilities.DisplayActors([Utilities.getPolyDataActor(tooth1), Utilities.getPolyDataActor(tooth2)])


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
        for x in np.arange(x1, xMid, (xMid - x1) / num_steps):
            print("1")
            booleanFilter.SetInputData(0, tooth1)
            booleanFilter.SetInputData(1, tooth2)
            booleanFilter.Update()
            if booleanFilter.GetNumberOfIntersectionPoints() > 0:
                break

            print("2")

            x_pos1, x_pos2 = (x, x2 + x1 - x)
            y_pos1, y_pos2 = (x_pos1 * slopeY + interceptY, x_pos2 * slopeY + interceptY)
            z_pos1, z_pos2 = (x_pos1 * slopeZ + interceptZ, x_pos2 * slopeZ + interceptZ)

            print("3")

            tooth1 = Utilities.setPolyDataCenter(tooth1, x_pos1, y_pos1, z_pos1)
            tooth2 = Utilities.setPolyDataCenter(tooth2, x_pos2, y_pos2, z_pos2)

            print("4")

            if 12 == id1 and 11 == id2:
                Utilities.DisplayActors([Utilities.getPolyDataActor(tooth1),
                                         Utilities.getPolyDataActor(tooth2)])

        print("DONE")

        if booleanFilter.GetNumberOfIntersectionPoints() > 0:
            return booleanFilter.GetOutput().GetCenter()
        else:
            return None

    def __orient_single_tooth(self,
                              id_mesh_dict: Dict[int, vtkPolyData],
                              treatment_json: Dict,
                              tooth_id: int) -> vtkPolyData:
        toothPolyData: vtkPolyData = id_mesh_dict[tooth_id]
        axes: np.ndarray = np.asarray(treatment_json['modellingData'][str(tooth_id)]['axes'])
        angulation_axis = np.matmul(axes[0:3], self.__matrix)

        directionX = 1 if angulation_axis[0] > 0 else -1
        point_horizontal = np.asarray([directionX, 0, 0])
        data = Utilities.setPolyDataCenter(toothPolyData, 0, 0, 0)

        projection = angulation_axis * np.asarray([1, 0, 1])
        yRotateAngle = Utilities.angle_between_vectors(point_horizontal, projection)
        yRotateAngle *= -1 if projection[2] > point_horizontal[2] else 1
        yRotateAngle = (180 - yRotateAngle) if tooth_id in Utilities.UPPER_TEETH else yRotateAngle

        angle = np.deg2rad(yRotateAngle)
        sin, cos = math.sin(angle), math.cos(angle)
        M = np.array([[cos,  0,  sin],
                      [0,    1,    0],
                      [-sin, 0,  cos]])

        data = Utilities.rotatePolyData(data, 0, yRotateAngle, 0)
        angulation_axis = np.matmul(angulation_axis, M.T)
        projection = angulation_axis * np.asarray([1, 0, 1])

        zRotateAngle = Utilities.angle_between_vectors(angulation_axis, projection)
        zRotateAngle *= 1 if angulation_axis[1] > projection[1] else -1

        return Utilities.rotatePolyData(data, 0, 0, zRotateAngle)

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
                    # print(f"Processing({id1}, {id2})")
                    points_dict[UnorderedPair(id1, id2)] = Worker.get_teeth_contact_point(tooth1, tooth2, id1, id2)
        return points_dict

    '''
    The method calculates the contact points of adjacent pairs of teeth separately for both jaws.

    Algorithm description:
    1. The method for improving performance works in multi-process mode
    2. The number of child processes is equal to the number of real CPU Cores on this machine
       (calculated as multiprocessing.cpu_count() / 2)
    3. A list of pairs of teeth is being prepared for calculating points
    4. This list is divided into sublists in an amount equal to the number of child processes
    5. Each process is given a corresponding sublist of pairs for processing
    6. The results are stored in a Dict[Unordered Pair, Tuple] data structure
    '''
    def __get_contact_points_async(self,
                                   id_mesh_dict: Dict[int, vtkPolyData]) -> Dict[UnorderedPair, Tuple]:
        # Prepare tooth pairs for processing in multithreading mode:
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
                    # TODO: Do we need synchronization here?
                    bus_queue.put((UnorderedPair(id1, id2), Worker.get_teeth_contact_point(tooth1, tooth2)))

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
                       objWorker: ToothOBJFileReader,
                       treatment_dict: Dict):
        teeth_lengths = self.__get_teeth_lengths(objWorker.teethMapOriented, treatment_dict)
        contact_points = self.__get_contact_points(objWorker.teethMap)
        # contact_points = self.__get_contact_points_async(objWorker.teethMap)
        return teeth_lengths, contact_points
