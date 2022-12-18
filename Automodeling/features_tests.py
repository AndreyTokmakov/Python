import json
import logging
import math
import multiprocessing
import os
import os.path
# import datetime
import sys
import warnings

from math import cos, pi, sin
from pathlib import Path
from typing import Dict, List

from scipy import optimize
from scipy.spatial import ConvexHull

import numpy
import vtk

from shapely import ops
from shapely.geometry import LineString,MultiPoint,Polygon
from vtk.util import numpy_support
from sklearn.cluster import KMeans
from inspect import currentframe, getframeinfo
from optparse import OptionParser

warnings.simplefilter(action='ignore', category=FutureWarning)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('features_extraction')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

####################################################################################################################################
#                                                      Utilities                                                                   #
####################################################################################################################################

def is_int(instr: str) -> bool:
    """Is int check

    Check if the provided value is an integer

    :param instr: Input value
    :type instr: str
    :returns: True or Fasle
    :rtype: {Bool}
    """
    try:
        int(instr)
        return True
    except:
        return False


def dist_to_circle_sum(R: float,
                       center: numpy.ndarray,
                       points: numpy.ndarray) -> float:
    """
    Calculate sum of distances from points to circle

    :param R: (3,) circle radius
    :param center: (3,) circle center
    :param points: (N, 3) points
    """
    dists_to_center = numpy.sqrt(numpy.square(points - center).sum(axis=-1))
    dists_to_circle = numpy.abs(dists_to_center - R)
    return dists_to_circle.sum()


def vector_l2_norm(vec: numpy.ndarray) -> float:
    """Vector normalisation

    Normalises provided vector to float

    :param vec: vector with the size 3
    :type vec: numpy.ndarray
    :returns: Normalised vector as float
    :rtype: {float}
    """
    return math.sqrt(numpy.square(vec).sum())


def dist(point_1: numpy.ndarray, point_2: numpy.ndarray) -> float:
    """Distance between points

    Computes distance between 2 points

    :param point_1: Point 1 coordinate
    :type point_1: numpy.ndarray
    :param point_2: Point 2 coordinate
    :type point_2: numpy.ndarray
    :returns: Distance as float
    :rtype: {float}
    """
    return vector_l2_norm(point_2 - point_1)


def calc_R(c: numpy.ndarray,
           x: numpy.ndarray,
           y: numpy.ndarray) -> numpy.ndarray:
    """
    Calculate the distance of each 2D points from the center (xc, yc)
    
    :param c: (2,) circle center
    :param x: point x coordinate
    :param y: point y coordinate
    """
    xc, yc = c
    return numpy.sqrt((x - xc)**2 + (y - yc)**2)


def f_2(c: numpy.ndarray,
        x: numpy.ndarray,
        y: numpy.ndarray) -> numpy.ndarray:
    """
    Calculate the algebraic distance between the data points and the mean circle centered at c=(xc, yc)
    
    :param c: (2,) circle center
    :param x: point x coordinate
    :param y: point y coordinate
    """
    Ri = calc_R(c, x, y)
    return Ri - Ri.mean()


def unit_vector(vector: numpy.ndarray) -> numpy.ndarray:
    """
    Returns the unit vector of the vector

    :param vector: (N,) vector
    """
    return vector / vector_l2_norm(vector)


def angle_between(v1, v2):
    """
    Returns the angle in radians between vectors
    
    :param v1: (N,) vector
    :param v2: (N,) vector
    """
    v1_u = unit_vector(v1)
    v2_u = unit_vector(v2)
    return numpy.arccos(numpy.clip(numpy.dot(v1_u, v2_u), -1.0, 1.0))


def angle(v1, v2):
    """Get angle between two vectors (in radians)

    :param v1: (N,) vector
    :param v2: (N,) vector
    :return: float angle in radians
    """
    return math.acos(numpy.dot(v1, v2) / (vector_l2_norm(v1) * vector_l2_norm(v2)))


def rotation(A: numpy.ndarray,
             B: numpy.ndarray) -> numpy.ndarray:
    """Rotation from vec A to vec B

    Calculates rotation between 2 vectors

    :param A: vector with the size 3
    :type A: numpy.ndarray
    :param B: vector with the size 3
    :type B: numpy.ndarray
    :returns: 3x3 rotation matrix
    :rtype: {numpy.ndarray}
    """
    def ssc(v):
        return numpy.asarray([
            [0, -v[2], v[1]],
            [v[2], 0, -v[0]],
            [-v[1], v[0], 0]])
    tmp = ssc(numpy.cross(A, B))
    RU = numpy.eye(3) + tmp + tmp @ tmp / (1 + numpy.dot(A, B))
    return RU


def get_rotation_matrix(axis, theta):
    """ calculate rotation matrix along give axis to angle theta """
    axis = numpy.asarray(axis)
    axis = axis / math.sqrt(numpy.dot(axis, axis))
    a = math.cos(theta / 2.0)
    b, c, d = -axis * math.sin(theta / 2.0)
    aa, bb, cc, dd = a * a, b * b, c * c, d * d
    bc, ad, ac, ab, bd, cd = b * c, a * d, a * c, a * b, b * d, c * d
    return numpy.array([[aa + bb - cc - dd, 2 * (bc + ad), 2 * (bd - ac)],
                     [2 * (bc - ad), aa + cc - bb - dd, 2 * (cd + ab)],
                     [2 * (bd + ac), 2 * (cd - ab), aa + dd - bb - cc]])


def chunks_generator(l, n):
    """Chunk generator

    Generated n chunks from l

    :param l: Number of chunks
    :type l: numpy.ndarray
    :param n: number of chunks
    :type n: int
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def save_features(path: str,
                  id_mesh_dict: Dict,
                  features_dict: Dict):
    """Save tooth features as json file

    Saves tooth features as JSON file with the following structure:
    {
        'hill_points': [],
        'cutting_edge': [],
        'fissures': []
    }

    :param path: Path where to save
    :type path: str
    :param id_mesh_dict: Dictionary with Tooth ID
    :type id_mesh_dict: Dict
    :param features_dict: Extracted features as json
    :type features_dict: Dict
    """
    new_features_dict = {}
    for key in id_mesh_dict:
        if not is_int(key):
            continue
        hill_points = features_dict[key]['hill_points']
        points = numpy_support.vtk_to_numpy(id_mesh_dict[key]['mesh'].GetPoints().GetData())
        new_features_dict[key] = {
                'hill_points': [],
                'cutting_edge': [],
                'fissures': []
        }
        for point in hill_points:
            new_features_dict[key]['hill_points'].append(id_mesh_dict[key]['mesh'].GetPoint(point))
        fissures = features_dict[key]['fissures']
        new_fissures = []
        if fissures:
            for fissure in fissures:
                new_fissure = []
                if fissure:
                    for point in fissure:
                        new_fissure.append(points[point].tolist())
                    new_fissures.append(new_fissure)
        new_features_dict[key]['fissures'] = new_fissures
        cutting_edge = features_dict[key]['cutting_edge']
        for point in cutting_edge:
            new_features_dict[key]['cutting_edge'].append(id_mesh_dict[key]['mesh'].GetPoint(point))
    with open(path, 'wt') as outfile:
        json.dump(new_features_dict, outfile)


def line_most_remote_points(line: numpy.ndarray) -> numpy.ndarray:
    """Compute furthest points

    Calcualtes 2 points of the line
    that are the furthest away from each other

    :param line: Line as array of points
    :type line: numpy.ndarray
    :returns: Array with size 2 containing fount points
    :rtype: {numpy.ndarray}
    """
    arrays = [line for _ in range(line.shape[0])]
    line_stack = numpy.stack(arrays, axis=1)
    dist_matrix = (numpy.square(line_stack - line).sum(axis=-1))
    result = numpy.zeros((2, 3))
    tmp_argmax = dist_matrix.argmax()
    result[0] = line[tmp_argmax // line.shape[0]]
    result[1] = line[tmp_argmax % line.shape[0]]
    return result


####################################################################################################################################
#                                                  Isolines filter                                                                 #
####################################################################################################################################


class IsoclinesFilter:

    """
    Compute isoclines of crown mesh.

    1. Cut specified 3D triangular mesh with plane
    2. Compute resulting isoclines
    3. Find series of nested isoclines
    """

    def __init__(self,
                model: vtk.vtkPolyData,
                normal=(0.0, 1.0, 0.0),
                remove_nonclosed=True,
                isoclines_num=30):
        """
        Create filter

        :param model: 3D triangular mesh
        :param normal: normal of plane to cut model
        :param remove_nonclosed: if True, remove non closed isoclines
        :param isoclines_num: number of isoclines to compute (defore removing not closed ones)
        """
        self.model = model
        self.isoclines_num = isoclines_num
        self.normal = normal
        self.__extract_isoclines()

    def __extract_isoclines(self) -> None:
        print("==================================================__extract_isoclines() ==================================================")
        centroid = get_centroid(self.model)

        print(f'centroid = {centroid}')

        # create plane
        plane = vtk.vtkPlane()
        plane.SetOrigin(centroid)
        plane.SetNormal(*self.normal)

        # print(plane)

        # compute bounding box
        bounds = self.model.GetBounds()
        min_bound = bounds[::2]
        max_bound = bounds[1::2]

        max_z_dist = max_bound[1] - centroid[1]
        min_z_dist = centroid[1] - min_bound[1]

        print(f"bounds = {bounds}")
        print(f"min_bound = {min_bound}")
        print(f"max_bound = {max_bound}")
        print(f"max_z_dist = {max_z_dist}")
        print(f"min_z_dist = {min_z_dist}")
        print(f"isoclines_num = {self.isoclines_num}")
        

        # cut model with planes
        cutter = vtk.vtkCutter()
        cutter.SetCutFunction(plane)
        cutter.SetInputData(self.model)
        cutter.GenerateValues(self.isoclines_num + 2, -min_z_dist, max_z_dist)
        cutter.Update()

        # print(cutter)

        # stripe contours
        self.contour_stripper = vtk.vtkStripper()
        self.contour_stripper.SetInputConnection(cutter.GetOutputPort())
        ''' Можно ли использовать JoinContiguousSegmentsOn() вместо __combine_contours() '''
        self.contour_stripper.JoinContiguousSegmentsOn()  
        self.contour_stripper.Update()

        # convert vtk array to numpy arrays
        contour_stripper_out = self.contour_stripper.GetOutput()
        lines_num = contour_stripper_out.GetNumberOfLines()
        lines_np = vtk.util.numpy_support.vtk_to_numpy(contour_stripper_out.GetLines().GetData())
        points =   vtk.util.numpy_support.vtk_to_numpy(contour_stripper_out.GetPoints().GetData())

        print(f"\nlines_num = {lines_num}")
        print("--------------------------------------------- lines_np----------------------------------------------------------------------")
        print(f"len = {len(lines_np)}")
        print(f"lines_np = {lines_np}")

        '''
        index = 0
        for l in lines_np:
            print(f'lines[{index}] = {l}')
            index += 1
        '''

        ######## combine contours and remove non-closed ones #####

        ''' Понять что тут происходит и зачем???? '''
        print("--------------------------------------------- getting_lines ---------------------------------------------------------------------")
        line_ind = 0
        self.index_lines = []
        for _ in range(lines_num):

            id   = lines_np[line_ind] + 1
            line = lines_np[line_ind + 1: line_ind + id]

            # print(f'id = {id}, line_ind = {line_ind}, lines_np[{line_ind}] = {lines_np[line_ind]}, [{line_ind + 1}: {line_ind + id}]')

            line_ind += id
            if line.size:
                self.index_lines.append(line)

        print(f"\nself.index_lines = {len(self.index_lines)}")
        self.__combine_contours()
 
        print(f"\nself.index_lines = {len(self.index_lines)}")
        self.__remove_non_closed_contours()

        print(f"self.index_lines = {len(self.index_lines)}")


        print("--------------------------------------------- points ----------------------------------------------------------------------")
        print(f"len = {len(points)}")
        print(f"points = {points}")

        self.z_max = points[0, 1]
        self.z_min = points[0, 1]
        self.lines = []
        for index_line in self.index_lines:
            line = points[index_line]
            self.lines.append(line)
            if line[0, 1] > self.z_max:
                self.z_max = line[0, 1]
            if line[0, 1] < self.z_min:
                self.z_min = line[0, 1]

        #print(f"\nself.lines = {self.lines}")

    def __remove_non_closed_contours(self) -> None:
        # if first point != last point, remove contour
        print("================================================== __remove_non_closed_contours ==================================================")
        new_lines = []
        for line in self.index_lines:
            if line[0] == line[-1]:
                new_lines.append(line)
        self.index_lines = new_lines

    def __combine_contours(self) -> None:
        """
        Combine connected contours
        """
        print("================================================== __combine_contours ==================================================")

        first_points = [line[0]  for line in self.index_lines]
        last_points  = [line[-1] for line in self.index_lines]
        line_ind = 0

        # print(f"first_points: {first_points}")
        # print(f"last_points: {last_points}")
        # print(f"self.index_lines: {self.index_lines}")
        # print(f"len : {len(self.index_lines)}")

        while line_ind < len(self.index_lines):
            print(f'line_ind = {line_ind}, len : {len(self.index_lines)}')
            line = self.index_lines.pop(line_ind)
            first_point = first_points.pop(line_ind)
            last_point = last_points.pop(line_ind)

            # first point match first point of other contour -> connect
            if first_point in first_points:
                ind_to_stripe = first_points.index(first_point)

                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)

                new_line = numpy.concatenate([line_to_stripe[::-1][1:], line])
                
                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])

            # first point match last point of other contour -> connect
            elif first_point in last_points:
                ind_to_stripe = last_points.index(first_point)

                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)

                new_line = numpy.concatenate([line_to_stripe, line[1:]])

                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])

            # last point match first point of other contour -> connect
            elif last_point in first_points:
                ind_to_stripe = first_points.index(last_point)

                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)

                new_line = numpy.concatenate([line, line_to_stripe[1:]])

                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])

            # last point match last point of other contour -> connect
            elif last_point in last_points:
                ind_to_stripe = last_points.index(last_point)

                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)

                new_line = numpy.concatenate([line, line_to_stripe[::-1][1:]])
                
                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])
            else:
                self.index_lines.insert(line_ind, line)
                first_points.insert(line_ind, first_point)
                last_points.insert(line_ind, last_point)
                line_ind += 1

    def get_isoclines(self) -> List[numpy.ndarray]:
        """
        Get isoclines

        :return: numpy.ndarray(N_i, 3) for each isocline
        """
        return self.lines

    def get_index_isoclines(self) -> List[numpy.ndarray]:
        """
        Get isoclines

        :return: numpy.ndarray(N_i,) - indexes of points in model for each isocline
        """
        return self.index_lines

    def visualize_isoclines(self) -> None:
        """
        Visualize computed isolines using VTK library
        """
        # create mapper
        input_mapper = vtk.vtkPolyDataMapper()
        input_mapper.SetInputData(self.model)
        cutter_mapper = vtk.vtkPolyDataMapper()
        cutter_mapper.SetInputConnection(self.contour_stripper.GetOutputPort())
        cutter_mapper.ScalarVisibilityOff()

        # create actors
        input_actor = vtk.vtkActor()
        input_actor.GetProperty().SetColor(0.9, 0.9, 0.9)
        input_actor.SetMapper(input_mapper)
        plane_actor = vtk.vtkActor()
        plane_actor.GetProperty().SetColor(0.2, 0.2, 0.2)
        plane_actor.GetProperty().SetLineWidth(3)
        plane_actor.SetMapper(cutter_mapper)

        # create rendrer
        renderer = vtk.vtkRenderer()
        renderer.AddActor(plane_actor)
        renderer.AddActor(input_actor)

        # create window
        render_window = vtk.vtkRenderWindow()
        render_window.AddRenderer(renderer)
        render_window.SetSize(800, 800)

        # create interactor and start render
        interactor = vtk.vtkRenderWindowInteractor()
        interactor.SetRenderWindow(render_window)
        renderer.SetBackground(0.1, 0.2, 0.3)
        render_window.Render()
        interactor.Start()

    def export_to_pdf(self, filename: str) -> None:
        """
        Export computed isoclines to pdf

        :param filename: path to resulting pdf file
        """

        import matplotlib.pyplot as plt
        from matplotlib.colors import hsv_to_rgb

        plt.switch_backend('Qt5Agg')
        isoclines = self.get_isoclines()
        s = 1.0
        v = 0.9
        for isoline in isoclines:
            h = (120 * (isoline[0, 1] - self.z_min) / (self.z_max - self.z_min)) / 360
            rgb = hsv_to_rgb([h, s, v])
            plt.plot(
                    isoline[:, 0].tolist(), isoline[:, 2].tolist(),
                    color=rgb, linewidth=0.2)
        plt.savefig(filename)

    def get_polygons(self, threshold=True) -> list():
        """
        Convert computed isoclines to shapely polygons (with isoclines as borders).

        :param threshold: remove polygon if it's are if less then THRESHOLD_PART * mean polygon area
        """

        THRESHOLD_PART = 0.7

        polygon_list = []
        mean_area = 0.0
        for line_id, line in enumerate(self.lines):
            poly = Polygon(line[:, (0, 2)].tolist())
            polygon_list.append([poly, float(line[0, 1]), line_id])
            mean_area += poly.area
        polygon_list.sort(key=lambda tup: tup[1])
        if threshold:
            mean_area /= len(polygon_list)
            for polygon in polygon_list:
                if polygon[0].area > THRESHOLD_PART * mean_area:
                    polygon_list.remove(polygon)
        return polygon_list

    def get_nested_polygon_groups(self, order: str) -> list():
        """
        Get nested polygons

        :param order: one of 'down_up' or 'up_down'
        """
        polygons = self.get_polygons()
        polygon_groups = []
        polygon_ind = 0
        polygon_group_ind = 0
        while polygon_ind < len(polygons):
            polygon_groups.append([])
            # group polygons based on Z coordinate
            y_coord = polygons[polygon_ind][1]
            while polygon_ind < len(polygons) and y_coord == polygons[polygon_ind][1]:
                polygon_groups[polygon_group_ind].append(polygons[polygon_ind])
                polygon_ind += 1
            polygon_group_ind += 1
        nested_polygons = []
        if 'down_up' == order:
            # get upper 2/ 3 of polygons
            polygon_groups = polygon_groups[len(polygon_groups) // 3: len(polygon_groups)]
            for i in range(len(polygon_groups) - 1):
                group = polygon_groups[i]
                # iterate over polygons
                for polygon in group:
                    # iterate over polygons in upper group
                    for upper_polygon in polygon_groups[i + 1]:
                        # if upper in nested, create new nested group
                        if polygon[0].contains(upper_polygon[0]):
                            nested_flag = False
                            new_nested_groups = []
                            # if this polygon is already in some group, add it to that group
                            for nested_polygon_group in nested_polygons:
                                if polygon in nested_polygon_group:
                                    nested_flag = True
                                    if len(nested_polygon_group) - 1 == nested_polygon_group.index(polygon):
                                        nested_polygon_group.append(upper_polygon)
                                    else:
                                        new_nested_groups.append(
                                                nested_polygon_group[:nested_polygon_group.index(polygon)+ 1] + [upper_polygon, ])
                            if not nested_flag:
                                nested_polygons.append([polygon, upper_polygon])
                            else:
                                nested_polygons += new_nested_groups
        elif 'up_down' == order:
            # same as 'down_up', but in reverse order
            polygon_groups = polygon_groups[: len(polygon_groups) * 2 // 3]
            for i in range(len(polygon_groups) - 1, 0, -1):
                group = polygon_groups[i]
                for polygon in group:
                    for upper_polygon in polygon_groups[i - 1]:
                        if polygon[0].contains(upper_polygon[0]):
                            nested_flag = False
                            new_nested_groups = []
                            for nested_polygon_group in nested_polygons:
                                if polygon in nested_polygon_group:
                                    nested_flag = True
                                    if len(nested_polygon_group) - 1 == nested_polygon_group.index(polygon):
                                        nested_polygon_group.append(upper_polygon)
                                    else:
                                        new_nested_groups.append(
                                                nested_polygon_group[:nested_polygon_group.index(polygon)+ 1] + [upper_polygon, ])
                            if not nested_flag:
                                nested_polygons.append([polygon, upper_polygon])
                            else:
                                nested_polygons += new_nested_groups
        else:
            log.error('Unknown order parameter')
            return None

        return nested_polygons

    def get_hills(self,
                  order: str,
                 clusters_num: int) -> List[Polygon]:
        """Get cusp polygon

        Get cusps i. e. internal polygons of nested polygon group
        Because the actual number of nested isolines can vary from expected - we clusterise them.

        :param order: "up_down" or "down_up" specifies the order that we look into the isolines
        :type order: str
        :param clusters_num: Number of expected cusps (depending on the tooth class)
        :type clusters_num: int
        :returns: List of cusp polygons
        :rtype: {List[Polygon]}
        """
        print("get_hills()");

        # Get nested polygons for given order (the polygons can be nested by Z+ or Z- depending on the arch type)
        nested_polygons_down_up = self.get_nested_polygon_groups(order=order)

        if not nested_polygons_down_up:
            log.error("get_hills: Can't find any hills")
            return None

        # get centroids of internal polygons
        candidates_centroids = []
        candidates_list = []
        centroid = get_centroid(self.model)
        for ind, nested_polygon_group in enumerate(nested_polygons_down_up):
            hill_candidate = nested_polygon_group[-1]
            candidate_line = self.get_isoclines()[hill_candidate[2]]
            candidate_centroid = candidate_line.sum(axis=0) / candidate_line.shape[0]
            # The centroids that we found shoud me at least 1mm away from the centroid of the model
            # This is to filter out the points that are not the main cusps that we're looking for
            # (like smaller cusps near the contact points on molars or smaller cusps hidden in fissures)
            if ('down_up' == order and candidate_centroid[1] > centroid[1] + 1.0)\
                    or ('up_down' == order and candidate_centroid[1] < centroid[1] - 1.0):
                candidates_list.append(nested_polygon_group)
                candidates_centroids.append(candidate_centroid)
        candidates_centroids = numpy.asarray(candidates_centroids)

        if len(candidates_list) < clusters_num:
            clusters_num = len(candidates_list)

        # clusterize centroids using KMeans algorithm
        kmeans = KMeans(n_clusters=clusters_num).fit(candidates_centroids)

        # Gather cluster centroids into an array
        clusters = [[] for i in range(clusters_num)]
        for ind, candidate in enumerate(candidates_list):
            clusters[kmeans.labels_[ind]].append(candidate)

        # Populate centroid cluster array
        hills = []
        for cluster in clusters:
            if cluster:
                cluster.sort(key=lambda tup: tup[-2][1])
                if 'down_up' == order:
                    hills.append(cluster[-1][-2])
                elif 'up_down' == order:
                    hills.append(cluster[0][-2])
        return hills

    def dump(self, path: str) -> None:
        """
        Write isoclines to JSON

        :param path: path to JSON
        """
        lines = [line.tolist() for line in self.lines]
        json.dump(lines, open(path, 'wt'))


####################################################################################################################################


def get_symmetry_axis_circle_projection(
    mesh: vtk.vtkPolyData,
    tooth_id: int) -> List[int]: #numpy.ndarray:
    """Get symmetry axes

    Computes symmetry axes by projecting boundary points onto a plane.

    Iteratively:
    - Apply rotation
    - project points onto a plane
    - fit circle using least squares
    - Compute sum of distances to fitted circle

    The fuction does 50 iterations of the circle fitting algorithm

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param tooth_id: Tooth ID as in FDI classification
    :type tooth_id: int
    :returns: Vertical symmetry axis as numpy.ndarray
    :rtype: {numpy.ndarray}
    """


    print(f" get_symmetry_axis_circle_projection ==================== tooth_id = {tooth_id} =============")
    #print("{0}: get_symmetry_axis_circle_projection() entered".format(datetime.date.today()))
    ANGLE_NUM = 50 # 100 old!!

    initial_vector = numpy.asarray([1.0, 0.0])
    rotation_values = numpy.linspace(-45.0, 45.0, 45) # numpy.linspace(-45.0, 45.0, 90) old
    dists = []
    angles = []
    rotation_angles = []
    centroid = get_centroid(mesh)

    print("   centroid = " + str(centroid))

    points     = numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    polys_data = numpy_support.vtk_to_numpy(mesh.GetPolys().GetData())
    polys_data = polys_data.reshape(polys_data.shape[0] // 4, 4)[..., 1:].flatten()

    print("   len                 = " + str(len(polys_data)))
    print("   polys_data.shape[0] = " + str(polys_data.shape[0]))

    indexes = numpy.unique(polys_data)
    points = points[indexes]
    points -= centroid

    # Start fitting iterations
    for i in range(ANGLE_NUM):
        angle = 360 / ANGLE_NUM * i
        angle_rad = float(angle) * pi / 180
        rotation_matrix = numpy.asarray([
            [cos(angle_rad), -sin(angle_rad)],
            [sin(angle_rad), cos(angle_rad)]
        ])
        # Apply first rotation (Y axis)
        rotation_axis = rotation_matrix.dot(initial_vector)
        #print(f"   angle: [{i}, {angle_rad}], Axis:  {rotation_axis}")
        for j in range(rotation_values.shape[0]):
            angles.append(angle)
            rotation_angles.append(rotation_values[j])
            rotation_matrix = get_rotation_matrix(numpy.asarray((rotation_axis[0], 0, rotation_axis[1])),rotation_values[j] * pi / 180)

            # print(f"      j: {j}. angle: {angle}| Values: {rotation_values[j]} | matrix: {rotation_matrix}")
            
            # Apply second rotation (rotated X axis)
            points_rotated = rotation_matrix.dot(points.T).T
            
            # Project shape onto a plane
            points_rotated_proj = points_rotated[..., [0, 2]]

            # Make ConvexHull for the projected object
            hull = ConvexHull(points_rotated_proj)
            x = points_rotated_proj[hull.vertices, 0]
            y = points_rotated_proj[hull.vertices, 1]

            # Find center of projected object
            x_m = x.mean()
            y_m = y.mean()
            center_estimate = x_m, y_m

            # Fit circle onto projected object
            center_2, ier = optimize.leastsq(f_2, center_estimate, args=(x, y))
            Ri_2 = calc_R(center_2, x, y)
            R_2 = Ri_2.mean()

            # Compute distances to circle and add them to a list
            dists.append(dist_to_circle_sum(R_2, center_2, points_rotated_proj[hull.vertices]))

    # Get instance best fitted with the circle (that looks more like a circle)
    min_index = dists.index(min(dists))

    # Compute rotation axis
    angle = angles[min_index]

    ''' TODO: Why 'angle' variable is not used here '''
    angle_rad = float(360 / ANGLE_NUM * i) * pi / 180
    # angle_rad = float(360 / ANGLE_NUM * angle) * pi / 180

    rotation_matrix = numpy.asarray([
        [cos(angle_rad), -sin(angle_rad)],
        [sin(angle_rad), cos(angle_rad)]]
    )

    rotation_axis = rotation_matrix.dot(initial_vector).tolist()
    rotation_matrix = get_rotation_matrix(
        numpy.asarray((rotation_axis[0], 0, rotation_axis[1])),
        -angle_rad
    )
    # Compute vertical symmetry axis
    symmetry_axis = rotation_matrix.dot(numpy.asarray((0.0, 1.0, 0.0)).T).T

    # Add axes to result base on arch type ("upper" or "lower")
    if symmetry_axis[1] < 0 and tooth_id // 10 in (3, 4):
        symmetry_axis = -symmetry_axis
    elif symmetry_axis[1] > 0 and tooth_id // 10 in (1, 2):
        symmetry_axis = -symmetry_axis
    else:
        print(f" ****************** get_symmetry_axis_circle_projection *************** skipping {tooth_id} tooth")
    return symmetry_axis.tolist()


def get_symmetry_axis(mesh: vtk.vtkPolyData,
                      tooth_id: int,
                      hill_point=0,
                      cutting_edge=None) -> List[int]: # numpy.ndarray:
    """Get symmetry axis

    Compute symmetry axes using isolines

    :param mesh: Input tooth mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param tooth_id: Tooth id as FDI label
    :type tooth_id: int
    :param hill_point: Cusp index, defaults to 0
    :type hill_point: number, optional
    :param cutting_edge: Edge polyline points index, defaults to None
    :type cutting_edge: numpy.ndarray, optional
    :returns: List of 3 floats [float, float, float]
    :rtype: {List}
    """

    print(f" get_symmetry_axis ==================== tooth_id = {tooth_id} =============")
    # print("{0}: get_symmetry_axis() entered".format(datetime.date.today()))
    # print(f"{mesh}")

    ISOCLINE_NUM = 100 # todo new

    # Compute 100 isolines for given mesh
    isoclines_filter = IsoclinesFilter(mesh, isoclines_num=ISOCLINE_NUM)
    lines = isoclines_filter.get_isoclines()
    # print(f"Lines = {lines}")

    
    # Find longest closed isoline
    max_line_len = max(map(lambda x: x.shape[0], lines))
    lines_np = numpy.zeros((len(lines), max_line_len, 3))
    for i, line in enumerate(lines):
        lines_np[i, :line.shape[0], :] = line
    # Group isolined sorted by Z coords
    unique_z_coords = numpy.unique(lines_np[..., 1])
    new_lines = []
    for z_coord in unique_z_coords:
        if 1 == numpy.count_nonzero(lines_np[:, 0, 1] == z_coord):
            new_line = lines_np[lines_np[:, 0, 1] == z_coord][0]
            new_line = new_line[new_line != numpy.asarray((.0, .0, .0))]
            new_line = new_line.reshape((new_line.shape[0] // 3, 3))
            new_lines.append([new_line, z_coord])
    new_lines = sorted(new_lines, key=lambda x: x[1])

    # Sort Z-sorted isolines by line length
    new_lines_by_shape = sorted(new_lines, key=lambda x: x[0].shape[0])

    # Reverse the array if dealing with lower jaw
    if tooth_id // 10 in (3, 4):
        new_lines = new_lines[::-1]
    # Select shortest isoline
    new_lines = [line[0] for line in new_lines]
    new_lines_by_shape = [line[0] for line in new_lines_by_shape]

    # Select centroids of the fifth and tenth lines
    centroid_1 = get_line_centroid(new_lines_by_shape[-(len(new_lines) // 5)])
    centroid_2 = get_line_centroid(new_lines_by_shape[-(len(new_lines) // 10)])

    # Get mesh points
    mesh_points = vtk.util.numpy_support.vtk_to_numpy(
        mesh.GetPoints().GetData())    
    # If edge_points were provided take edge_points and mesh centroid instead of isoline centroids
    if not cutting_edge is None:  # TODO move higher in this function
        centroid_1 = (mesh_points[cutting_edge[0]] +
                      mesh_points[cutting_edge[-1]]) / 2
        centroid_2 = get_centroid(mesh)

    # Compute and normalize vector that defines vertical symmetry axis
    direction_vec = centroid_2 - centroid_1
    direction_vec = direction_vec / vector_l2_norm(direction_vec)

    # Add axes to result base on arch type ("upper" or "lower")
    if direction_vec[1] < 0 and tooth_id // 10 in (3, 4):
        direction_vec = -direction_vec
    elif direction_vec[1] > 0 and tooth_id // 10 in (1, 2):
        direction_vec = -direction_vec
    else:
        print(f" ****************** get_symmetry_axis_circle_projection *************** skipping {tooth_id} tooth")
    return direction_vec.tolist()


def preprocess_mesh(mesh: vtk.vtkPolyData,
                    logging=None,
                    iter_num=1,
                    relaxation_factor=0.01,
                    decimation=True,
                    out_poly_num_coefficient=0.8,
                    poly_num=None
                    ) -> vtk.vtkPolyData:
    """Smooth mesh

    Smooth mesh using VTK tools

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param logging: Log
    :type logging: logging
    :param iter_num: Number of smoothing iterations
    :type iter_num: int
    :param relaxation_factor: Relaxation factor as float
    :type relaxation_factor: float
    :param decimation: decimation apply
    :type decimation: boolean
    :param out_poly_num_coefficient: decimation coefficient if need poly_num options
    :type out_poly_num_coefficient: float
    :param poly_num: decimation polys or None or 0 (use out_poly_num_coefficient)
    :type poly_num: int
    :returns: Smoothed mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """

    # OUT_POLY_NUM=60000 for old code preprocessing + RELAXATION_FACTOR=0.1
    # RELAXATION_FACTOR=0.1 or 0.01 for preprocessing

    print("preprocess_mesh: ")
    print(f"    iter_num = {iter_num}")
    print(f"    relaxation_factor = {relaxation_factor}")
    print(f"    decimation = {decimation}")
    

    print(f"Number of polys = {mesh.GetNumberOfPolys()}")
    

    if iter_num and iter_num > 0:
        if logging:
            logging.info(f'smooth iter_num={iter_num}, relaxation_factor={relaxation_factor}')
        smooth_filter = vtk.vtkSmoothPolyDataFilter()
        smooth_filter.SetInputData(mesh)
        smooth_filter.SetNumberOfIterations(iter_num)
        smooth_filter.SetRelaxationFactor(relaxation_factor)
        smooth_filter.Update()
        mesh = smooth_filter.GetOutput()

    print(f"Number of polys = {mesh.GetNumberOfPolys()}")        

    
    if decimation:
        num_of_polys = mesh.GetNumberOfPolys()
        out_poly_num = 0
        print(f"out_poly_num = {out_poly_num}")   
        if not poly_num or poly_num <= 0:
            out_poly_num = int(mesh.GetNumberOfCells() * out_poly_num_coefficient)
            if logging:
                logging.info(f'decimate {num_of_polys} to {out_poly_num} opt: coef={out_poly_num_coefficient}')
        else:
            out_poly_num = poly_num
            if logging:
                logging.info(f'decimate {num_of_polys} to {out_poly_num}')

        if out_poly_num > 0 and num_of_polys > out_poly_num:
            decimate = vtk.vtkQuadricDecimation()
            decimate.SetInputData(mesh)
            decimate.SetTargetReduction(float(num_of_polys - out_poly_num) / num_of_polys)
            decimate.Update()
            iter = 1
            if iter_num and iter_num > 0:
                iter = iter_num
            smooth_filter = vtk.vtkSmoothPolyDataFilter()
            smooth_filter.SetInputConnection(decimate.GetOutputPort())
            smooth_filter.SetNumberOfIterations(iter)
            smooth_filter.SetRelaxationFactor(relaxation_factor)
            smooth_filter.Update()
            mesh = smooth_filter.GetOutput()
        print(f"out_poly_num = {out_poly_num}")   
  
    return mesh
 

def get_line_centroid(line: numpy.ndarray):
    """Get centroid of a line

    Compute centroid from a provided line

    :param line: Line as nd.array
    :type line: numpy.ndarray
    :returns: Centroid coordinates as array with size 3
    :rtype: {numpy.ndarray}
    """
    centers = (line[:line.shape[0] - 1] + line[1:]) / 2
    diff = line[1:] - line[:line.shape[0] - 1]
    lengths = numpy.sqrt(numpy.square(diff).sum(axis=-1))
    centroid = numpy.sum(centers * numpy.dstack((lengths, lengths, lengths))[0], axis=0) / lengths.sum()
    return centroid


def list_intersection(list1:list(), list2:list()):
    """Intersect two lists"""
    return [item for item in list1 if item in list2]


def line_most_remote_points(line: numpy.ndarray) -> numpy.ndarray:
    """Compute furthest points

    Calcualtes 2 points of the line
    that are the furthest away from each other

    :param line: Line as array of points
    :type line: numpy.ndarray
    :returns: Array with size 2 containing fount points
    :rtype: {numpy.ndarray}
    """
    arrays = [line for _ in range(line.shape[0])]
    line_stack = numpy.stack(arrays, axis=1)
    dist_matrix = (numpy.square(line_stack - line).sum(axis=-1))
    result = numpy.zeros((2, 3))
    tmp_argmax = dist_matrix.argmax()
    result[0] = line[tmp_argmax // line.shape[0]]
    result[1] = line[tmp_argmax % line.shape[0]]
    return result


def lines_similarity_measure(line_1: numpy.ndarray, line_2: numpy.ndarray) -> float:
    """Lines similarity metric

    Measures lines similarity by computing
    For each point of line 1 (N)
    looks for the closest point in line 2 (M)
    and computes an (N,M) distance matrix

    :param line_1: (N,3) array
    :type line_1: numpy.ndarray
    :param line_2: (M,3) array
    :type line_2: numpy.ndarray
    :returns: Distance matrix between 2 lines
    :rtype: {float}
    """
    arrays = [line_1 for _ in range(line_2.shape[0])]
    line_1_stack = numpy.stack(arrays, axis=1)
    # Computing (N,M) distance matrix
    dist_matrix = (numpy.square(line_1_stack - line_2).sum(axis=-1))
    return dist_matrix.min(axis=-1).sum() / (line_1.shape[0] + line_2.shape[0])


def read_stl(mesh_path: str) -> vtk.vtkPolyData:
    """Read STL

    Reads STL mesh from disk

    :param mesh_path: Path to stl mesh
    :type mesh_path: str
    :returns: Mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """
    obj_reader = vtk.vtkSTLReader()
    obj_reader.SetFileName(mesh_path)
    obj_reader.Update()
    return obj_reader.GetOutput()


def read_obj_teeth(mesh_path: str) -> Dict[int, vtk.vtkPolyData]:
    """Read OBJ teeth

    Read teeth object to returs a dictionary with individual teeth

    :param mesh_path: Path to obj mesh
    :type mesh_path: str
    :returns: Disctionary with teeth objects as VTK objects
    :rtype: {Dict[int, vtk.vtkPolyData]}
    """
    data_map = {}
    with open(mesh_path, 'rt') as infile:
        lines = infile.readlines()
        #print(f'lines length = {len(lines)}')

        n = 0;
        i = 0
        while i < len(lines) and 'g' == lines[i].split()[0]:
            jaw_type = lines[i].split()[1]
            i += 1
            n += 1;
            while i < len(lines) and 'o' == lines[i].split()[0]:
                objectpid = int(lines[i].split()[1][1:])
                data_map[objectpid] = vtk.vtkPolyData()
                points = []
                i += 1
                while i < len(lines) and 'v' == lines[i].split()[0]:
                    pts = [float(s) for s in lines[i][2:].split()]
                    # print(type(pts))
                    points.append(pts)
                    i += 1
                    
                vtk_points = vtk.vtkPoints()
                # vtk_points.SetNumberOfPoints(len(points))
                for j, point in enumerate(points):
                    vtk_points.InsertNextPoint(point)
                    # print(point)


                data_map[objectpid].SetPoints(vtk_points)


                cells = []
                while i < len(lines) and 'f' == lines[i].split()[0]:
                    cell = [int(s) + len(points) if int(s) < 0 else int(s) for s in lines[i][2:].split()];
                    cells.append(cell)
                    i += 1



                vtk_cells = vtk.vtkCellArray()
                for j in range(len(cells)):
                    vtk_cells.InsertNextCell(3, cells[j])
                    # print(cells[j])

                data_map[objectpid].SetPolys(vtk_cells)


    # print(f'n = {n}')
    return data_map


def get_centroid(mesh: vtk.vtkPolyData) -> numpy.ndarray:
    """Get centroid

    Compute centroid for provided mesh

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :returns: Centroid coordinates as array with size 3
    :rtype: {numpy.ndarray}
    """
    polys = mesh.GetPolys()
    polys_data = numpy_support.vtk_to_numpy(polys.GetData())
    points = numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    polys_data = polys_data.reshape(polys_data.shape[0] // 4, 4)[..., 1:].flatten()
    polys_data = points[polys_data]
    polys_data = polys_data.reshape(polys_data.shape[0] // 3, 3, 3)
    centers = polys_data.sum(axis=-2) / 3
    diff_1 = polys_data[:, 1, :] - polys_data[:, 0, :]
    diff_2 = polys_data[:, 2, :] - polys_data[:, 0, :]
    crosses = numpy.cross(diff_1, diff_2)
    areas = 0.5 * numpy.sqrt(numpy.square(crosses).sum(axis=-1))
    centroid = numpy.sum(centers * numpy.dstack((areas, areas, areas))[0], axis=0) / areas.sum()
    return centroid


def get_hill_points(
        mesh: vtk.vtkPolyData,
        hills: List[Polygon],
        z_coords: List[float],
        order: str) -> List[int]:
    """Get cusp points

    Compute cusp points given an array of cusp polygons.

    :param mesh: Crown mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param hills: List of cusp polygons
    :type hills: List[Polygon]
    :param z_coords: List of Z coordinates of the provided polygons
    :type z_coords: List[float]
    :param order: "up_down" or "down_up" depending on what arch we're working with
    :type order: str
    :returns: List of point indexes in the mesh point array
    :rtype: {List[int]}
    """
    if not hills:
        log.error('No hills found')
        return None
    hill_points = []

    # Prepare point data from mesh
    points = vtk.util.numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    point_collection = MultiPoint(points[:, [0, 2]].tolist())

    # Find points that belong to all cusp polygons
    points_in_hills = hills[0].intersection(point_collection)
    for hill in hills[1:]:
        points_in_hill = hill.intersection(point_collection)
        points_in_hills = ops.cascaded_union([points_in_hills, points_in_hill])

    # Find one point that has the biggest(smallest) Z coord in a given cusp polygon
    for hill, z_coord in zip(hills, z_coords):
        intersection = hill.intersection(points_in_hills)
        geoms = []
        try:
            geoms = intersection.geoms
        except AttributeError:
            # Exception can be raised if there is only one point in the polygon
            geoms = [intersection]

        # If there are no mesh points inside the polygon
        # We search for a point that's closest to the mesh
        if not geoms:
            polygon_points = numpy.asarray(hill.exterior.coords.xy)
            point = numpy.asarray([polygon_points[0, 0], z_coord, polygon_points[1, 0]])
            hill_points.append(int(numpy.square(points - point).sum(axis=1).argmin()))
            continue

        # Collect point indexes for each fond point within the point scope of the mesh model
        tmp_ind = (points[:, [0, 2]] == geoms[0]).sum(axis=1).astype(bool)
        for i in range(1, len(geoms)):
            tmp_ind = numpy.logical_or(
                tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
        index_arr = numpy.argwhere(tmp_ind)[0]
        points_in_hill = points[index_arr]

        # Choose Z max or Z min point, depending on the arch type
        hill_point_ind = 0
        if 'up_down' == order:
            hill_point_ind = index_arr[points_in_hill[:, 1].argmax()]
        elif 'down_up' == order:
            hill_point_ind = index_arr[points_in_hill[:, 1].argmin()]
        else:
            log.error('Unknown order')
            return None
        hill_points.append(int(hill_point_ind))
    return hill_points


def get_fissures(
        mesh: vtk.vtkPolyData,
        hill_points: List[int],
        order='down_up') -> List[List[int]]:
    """Get tooth fissures

    Get all fissures of a given tooth.

    :param mesh: Crown mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param hill_points: Cusp points as returned by get_hill_points()
    :type hill_points: List[int]
    :param order: "up_down" or "down_up" depending on arch type, defaults to 'down_up'
    :type order: str, optional
    """
    points = vtk.util.numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())

    # Project points onto a 2D plane
    point_collection = MultiPoint(points[:, [0, 2]].tolist())

    # If there are 4 cusps - we're dealing with a molar
    # Molar has 2 fissures
    if 4 == len(hill_points):

        SEGM_NUM = 25
        INDENT = 1.0

        # Check that connection of cusp points produces a quadrangle
        hill_points_arr = points[hill_points]
        if LineString([hill_points_arr[0, [0, 2]], hill_points_arr[2, [0, 2]]]).intersects(
                LineString([hill_points_arr[1, [0, 2]], hill_points_arr[3, [0, 2]]])):
            hill_points = [
                    hill_points[0], hill_points[3],
                    hill_points[2], hill_points[1]]
        elif LineString([hill_points_arr[0, [0, 2]], hill_points_arr[3, [0, 2]]]).intersects(
                LineString([hill_points_arr[1, [0, 2]], hill_points_arr[2, [0, 2]]])):
            hill_points = [
                    hill_points[0], hill_points[1],
                    hill_points[3], hill_points[2]]
        elif LineString([hill_points_arr[0, [0, 2]], hill_points_arr[1, [0, 2]]]).intersects(
                LineString([hill_points_arr[2, [0, 2]], hill_points_arr[3, [0, 2]]])):
            hill_points = [
                    hill_points[0], hill_points[3],
                    hill_points[1], hill_points[2]]

        # Close the quad by appending the [0] point to the array
        hill_points.append(hill_points[0])
        hill_points_arr = points[hill_points]

        # Compute centers for each side of the quad with shape[4,2]
        mean_points = (hill_points_arr[:4] + hill_points_arr[1:]) / 2

        # Connect centers of each side (produces a cross)
        dircet_vec_1 = mean_points[2, [0, 2]] - mean_points[0, [0, 2]]
        dircet_vec_1 /= vector_l2_norm(dircet_vec_1)
        norm_vec_1 = numpy.asarray([dircet_vec_1[1], -dircet_vec_1[0]])
        dircet_vec_2 = mean_points[3, [0, 2]] - mean_points[1, [0, 2]]
        dircet_vec_2 /= vector_l2_norm(dircet_vec_2)
        norm_vec_2 = numpy.asarray([dircet_vec_2[1], -dircet_vec_2[0]])

        mean_points[2, [0, 2]] += dircet_vec_1
        mean_points[0, [0, 2]] -= dircet_vec_1
        mean_points[3, [0, 2]] += dircet_vec_2
        mean_points[1, [0, 2]] -= dircet_vec_2

        # Find fissure area on mesh surface (see illustration)
        points_1 = Polygon([
                    mean_points[0, [0, 2]] + INDENT * norm_vec_1,
                    mean_points[2, [0, 2]] + INDENT * norm_vec_1,
                    mean_points[2, [0, 2]] - INDENT * norm_vec_1,
                    mean_points[0, [0, 2]] - INDENT * norm_vec_1]).intersection(point_collection)
        points_2 = Polygon([
                    mean_points[1, [0, 2]] + INDENT * norm_vec_2,
                    mean_points[3, [0, 2]] + INDENT * norm_vec_2,
                    mean_points[3, [0, 2]] - INDENT * norm_vec_2,
                    mean_points[1, [0, 2]] - INDENT * norm_vec_2]).intersection(point_collection)

        """Fissure search in fissure area

        We take the fissure area, divide it into a number of segments (SEGM_NUM)
        and search for a point that has min or max Z coordinate (depending on arch type).
        The point seceltion process is similar to get_hill_points().
        """
        point_1 = mean_points[0, [0, 2]]
        min_points_1 = []
        for i in range(SEGM_NUM):
            point_2 = point_1 + dircet_vec_1 * dist(
                    mean_points[0, [0, 2]],
                    mean_points[2, [0, 2]]) / SEGM_NUM
            poly = Polygon([
                    point_1 + INDENT * norm_vec_1, point_2 + INDENT * norm_vec_1,
                    point_2 - INDENT * norm_vec_1, point_1 - INDENT * norm_vec_1])
            intersection = poly.intersection(points_1)
            try:
                geoms = intersection.geoms
            except AttributeError:
                geoms = [intersection]
            if not geoms:
                continue
            tmp_ind = (points[:, [0, 2]] == geoms[0]).sum(axis=1) == 2
            for i in range(1, len(geoms)):
                tmp_ind = numpy.logical_or(
                        tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
            index_arr = numpy.argwhere(tmp_ind)[0]
            points_in_poly = points[index_arr]
            min_point_ind = int(0)
            if 'up_down' == order:
                min_point_ind = index_arr[points_in_poly[:, 1].argmax()]
            elif 'down_up' == order:
                min_point_ind = index_arr[points_in_poly[:, 1].argmin()]
            else:
                log.warning('Unknown order')
                return None
            min_points_1.append(int(min_point_ind))
            point_1 = point_2

        # Repeat the process to find the second fissure
        point_1 = mean_points[1, [0, 2]]
        min_points_2 = []
        for i in range(SEGM_NUM):
            point_2 = point_1 + dircet_vec_2 * dist(
                    mean_points[1, [0, 2]],
                    mean_points[3, [0, 2]]) / SEGM_NUM
            poly = Polygon([
                    point_1 + INDENT * norm_vec_2, point_2 + INDENT * norm_vec_2,
                    point_2 - INDENT * norm_vec_2, point_1 - INDENT * norm_vec_2])
            intersection = poly.intersection(points_2)
            try:
                geoms = intersection.geoms
            except AttributeError:
                geoms = [intersection]
            if not geoms:
                continue
            tmp_ind = (points[:, [0, 2]] == geoms[0]).sum(axis=1) == 2
            for i in range(1, len(geoms)):
                tmp_ind = numpy.logical_or(
                        tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
            index_arr = numpy.argwhere(tmp_ind)[0]
            points_in_poly = points[index_arr]
            min_point_ind = int(0)
            if 'up_down' == order:
                min_point_ind = index_arr[points_in_poly[:, 1].argmax()]
            elif 'down_up' == order:
                min_point_ind = index_arr[points_in_poly[:, 1].argmin()]
            else:
                log.warning('Unknown order')
                return None
            min_points_2.append(int(min_point_ind))
            point_1 = point_2
        return [min_points_1, min_points_2]

    # If there are only 2 cusps, then we're dealing with a premolar. Thus we expect to find only one fissure.
    elif 2 == len(hill_points):

        SEGM_NUM = 20
        INDENT = 1.0

        # The process is the same as in the case of searching for 2 fissures on a molar
        hill_points_arr = points[hill_points]
        mean_point = (hill_points_arr[0, [0, 2]] + hill_points_arr[1, [0, 2]]) / 2
        norm_vec = hill_points_arr[1, [0, 2]] - hill_points_arr[0, [0, 2]]
        norm = vector_l2_norm(norm_vec)
        if not norm:
            log.warning('Hill point are too close')
            return None
        norm_vec /= vector_l2_norm(norm_vec)
        dircet_vec = numpy.asarray([norm_vec[1], -norm_vec[0]])
        points_in_box = Polygon([
                    mean_point - 2 * dircet_vec + INDENT * norm_vec,
                    mean_point + 2 * dircet_vec + INDENT * norm_vec,
                    mean_point + 2 * dircet_vec - INDENT * norm_vec,
                    mean_point - 2 * dircet_vec - INDENT * norm_vec]).intersection(
                            point_collection)

        point_1 = mean_point - 2 * dircet_vec
        min_points = []
        for i in range(SEGM_NUM):
            point_2 = point_1 + dircet_vec * 4 / SEGM_NUM
            poly = Polygon([
                    point_1 + INDENT * norm_vec, point_2 + INDENT * norm_vec,
                    point_2 - INDENT * norm_vec, point_1 - INDENT * norm_vec])
            intersection = poly.intersection(points_in_box)
            geoms = []
            try:
                geoms = intersection.geoms
            except AttributeError:
                geoms = [intersection]
            if not geoms:
                continue
            
            print ("************** DEBUG *******************")

            
            tmp_ind = (points[:, [0, 2]] == geoms[0]).sum(axis=1) == 2
            for i in range(1, len(geoms)):
                tmp_ind = numpy.logical_or(
                        tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
            index_arr = numpy.argwhere(tmp_ind)[0]
            points_in_poly = points[index_arr]
            min_point_ind = int(0)
            if 'up_down' == order:
                min_point_ind = index_arr[points_in_poly[:, 1].argmax()]
            elif 'down_up' == order:
                min_point_ind = index_arr[points_in_poly[:, 1].argmin()]
            else:
                log.error('Unknown order')
                return None
            min_points.append(int(min_point_ind))
            point_1 = point_2
        return [min_points]
    else:
        # TODO currently fissures are not used in auto modelling, so program execution interuption is not necessary
        log.warning('Only 2 or 4 hill points are supported')
        return None


def find_cutting_edge(
        mesh_points: numpy.ndarray,
        nested_isoclines: List[numpy.ndarray],
        order: str,
        use_three_point: bool=False,
        hill_point: int=None) -> List[int]:
    """Find cutting edge

    Find cutting edge on non-molar teeth.

    :param mesh_points: Mesh points as an (N,3) numpy.ndarray
    :type mesh_points: numpy.ndarray
    :param nested_isoclines: List of (M,3) ndarrays representing isolines
    :type nested_isoclines: List[numpy.ndarray]
    :param order: "down_up" or "up_down" depending on arch type
    :type order: str
    :param use_three_point: Edge search algorithm selection parameter, defaults to False
    :type use_three_point: bool, optional
    :param hill_point: Central cusp as mesh point index, defaults to None
    :type hill_point: int, optional
    :returns: List of point indexes that represent the cutting edge
    :rtype: {List[int]}
    """
    THRESHOLD = 1.7
    POINTS_NUM = 40

    # Look for similar neighbouring isolines
    similarities = numpy.zeros((len(nested_isoclines) - 1, ))
    for i in range(len(nested_isoclines) - 1, 0, -1):
        similarities[i - 1] = lines_similarity_measure(
                nested_isoclines[i - 1], nested_isoclines[i])
    count = 0
    # Look for a similarity "jump" that exceeds the THRESHOLD starting from the n-th isoline (n is set in POINTS_NUM constant)
    for i in range(similarities.shape[0] - 1, 0, -1):
        if count > POINTS_NUM and similarities[i] / similarities[i - 1] > THRESHOLD:
            break
        count += 1
    nested_group_len = len(nested_isoclines)
    cutting_edge = None

    # For each isoline after the "jump" we look for 2 points of the isoline that have the maximum distance between them
    if not use_three_point:
        # If we're NOT using "use_three_point" method. We connect neighboring distant points from all isolines.
        cutting_edge_len = 2 * (nested_group_len - i + 1)
        cutting_edge = numpy.zeros((cutting_edge_len, 3))
        for j in range(i - 1, nested_group_len):
            remote_points = line_most_remote_points(nested_isoclines[j])
            if remote_points[0, 0] < remote_points[1, 0]:
                cutting_edge[j - i + 1] = remote_points[0]
                cutting_edge[cutting_edge_len - 1 - j + i - 1] = remote_points[1]
            else:
                cutting_edge[j - i + 1] = remote_points[1]
                cutting_edge[cutting_edge_len - 1 - j + i - 1] = remote_points[0]
    else:
        # If we ARE using "use_three_point" method. We connect the remote and the center cusp (hill_point) points with straight lines
        cutting_edge = numpy.zeros((POINTS_NUM, 3))
        remote_points = line_most_remote_points(nested_isoclines[0])
        if remote_points[0, 0] < remote_points[1, 0]:
            cutting_edge[0] = remote_points[0]
            cutting_edge[POINTS_NUM // 2] = mesh_points[hill_point]
            cutting_edge[-1] = remote_points[1]
        else:
            cutting_edge[0] = remote_points[1]
            cutting_edge[POINTS_NUM // 2] = mesh_points[hill_point]
            cutting_edge[-1] = remote_points[0]
        for i in range(1, POINTS_NUM // 2):
            cutting_edge[i] = cutting_edge[0] + i *\
                    (cutting_edge[POINTS_NUM // 2] - cutting_edge[0]) / (POINTS_NUM // 2 - 1)
        for i in range(POINTS_NUM // 2 + 1, POINTS_NUM - 1):
            cutting_edge[i] = cutting_edge[POINTS_NUM // 2] + (i - POINTS_NUM // 2) *\
                    (cutting_edge[-1] - cutting_edge[POINTS_NUM // 2]) / (POINTS_NUM // 2 - 1)

    # For each point of the found cutting edge we look for the nearest point in the mesh
    # And poplulate the resulting list with point indexes
    cutting_edge_list = []
    for i in range(cutting_edge.shape[0]):
        cutting_edge_list.append(int(numpy.square(mesh_points - cutting_edge[i]).sum(axis=1).argmin()))
    return cutting_edge_list


def find_cutting_edge_iso_obb(
        mesh: vtk.vtkPolyData,
        tooth_id: int,
        isoclines_filter: IsoclinesFilter) -> List[int]:
    """Find cutting edge with OBB

    Find a cutting edge of a tooth using oriented bounding box for isolines.
    (we're only working with the lower arch teeth here)

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param tooth_id: Tooth id according to FDI notation system
    :type tooth_id: int
    :param isoclines_filter: IsoclinesFilter class instance
    :type isoclines_filter: IsoclinesFilter
    :returns: List of mesh point indexes that represent a cutting edge
    :rtype: {List[int]}
    """
    mesh_points = numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    lines = isoclines_filter.get_isoclines()

    # Sort isolines by Z coordinate
    lines = sorted(lines, key=lambda x: x[0, 1])
    if tooth_id // 10 in (3, 4):
        lines = lines[::-1]

    # Replace each isoline with an OBB of that isoline
    obbs = []
    new_lines = []
    for line in lines:
        corner, max_axis, mid_axis, min_axis, size = ([0.0, 0.0, 0.0] for i in range(5))
        vtk_points = vtk.vtkPoints()
        for i in range(line.shape[0]):
            vtk_points.InsertNextPoint(*line[i].tolist())
        vtk.vtkOBBTree.ComputeOBB(
            vtk_points,
            corner,
            max_axis,
            mid_axis,
            min_axis,
            size
        )
        if not math.isclose(numpy.linalg.norm(mid_axis), 0.0) and not math.isclose(numpy.linalg.norm(mid_axis), 0.0):
            new_lines.append(line)
            """OBB parameters

            We append the following parameters that define the flat OBB:
            - Corner of the box from which the box is built
            - 2 vectors that represent the sides of our flat OBB
            - area
            - relation of the OBB sides
            """
            obbs.append([
                corner,
                mid_axis,
                max_axis,
                numpy.linalg.norm(mid_axis) * numpy.linalg.norm(max_axis),
                min(numpy.linalg.norm(mid_axis), numpy.linalg.norm(max_axis))\
                    / max(numpy.linalg.norm(mid_axis), numpy.linalg.norm(max_axis))
            ])

    # Filter OBB structure based on area and relation of the OBB sides
    lines = new_lines
    idx = 0
    # We're moving from top to bottom and looking for small and narow OBBs
    while idx < len(obbs) and (obbs[idx][3] < 10.0 or obbs[idx][4] < 0.6):
        # When we find one that satisfies the condition - count them
        idx += 1

    # We take the midpoints of the narow sides of found OBBs
    cutting_edge = numpy.zeros((idx * 2, 3))
    for i in range(idx):
        corner = numpy.asarray(obbs[i][0])
        mid_axis = numpy.asarray(obbs[i][1])
        max_axis = numpy.asarray(obbs[i][2])
        cutting_edge[idx - i - 1] = corner + mid_axis / 2
        cutting_edge[idx + i] = corner + max_axis + mid_axis / 2

    # And search for closest points on the model to build tha cutting edge of the crown
    cutting_edge = cutting_edge[cutting_edge[:, 0].argsort()]
    cutting_edge_list = []
    for i in range(cutting_edge.shape[0]):
        cutting_edge_list.append(int(numpy.square(mesh_points - cutting_edge[i]).sum(axis=1).argmin()))
    return cutting_edge_list


def __extract_tooth_features_using_isoclines(
        tooth_id: int,
        isoclines_num: int,
        mesh: vtk.vtkPolyData) -> Dict:
    """Extract tooth features using isoclines analysis

    returns ::

        {
            'hill_points': List[int]
            'fissures': List[List[int]]
            'cutting_edge': List[int],
            'isoclines': List[List[int]]
        }

    :param tooth_id: id of tooth in FDI notation
    :param mesh: crown mesh
    :return compute features
    """

    log.info(tooth_id)

    # How many cusps are expected on each tooth
    id_hill_num = {
        8: 4, 7: 4, 6: 4,
        5: 2, 4: 2, 3: 1,
        2: 1, 1: 1
    }

    # Tooth numbering bases on FDI notation system
    lower_id = tuple(range(41, 49)) + tuple(range(31, 39))
    upper_id = tuple(range(11, 19)) + tuple(range(21, 29))

    # Which teeth are expected to have cutting edges
    cutting_edge_ids = tuple(range(41, 44)) + tuple(range(31, 34)) +\
        tuple(range(11, 14)) + tuple(range(21, 24))
    premolar_ids = [14, 24, 34, 44]

    # Get mesh points to VTK array
    mesh_points = numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    jaw_type = ''
    # Set isolines lookup based on arch type ("upper" or "lower")
    if tooth_id in upper_id:
        order = 'up_down'
        jaw_type = 'upper'
    elif tooth_id in lower_id:
        order = 'down_up'
        jaw_type = 'lower'

    # Specify local coordinate axis to compute isolines
    normal = [0.0, 1.0, 0.0]
    # Compute isolines
    isoclines_filter = IsoclinesFilter(
        mesh,
        isoclines_num=isoclines_num,
        normal=normal
    )
    isoclines = isoclines_filter.get_isoclines()

    # Prepare data structure for results
    result = {
        'hill_points': [],
        'fissures': [],
        'cutting_edge': [],
        'isoclines': [line.tolist() for line in isoclines_filter.get_isoclines()]
    }

    # Take nested isolines
    nested_polygons = isoclines_filter.get_nested_polygon_groups(order=order)
    nested_isoclines = [[isoclines[polygon[2]] for polygon in nested_polygon_group]\
        for nested_polygon_group in nested_polygons]

    """Search for the buccal cusp of a promolar that includes a fix for topology errors.

    When we're working at premolar, we know that a premolar has 2 major cusps.
    One on the lingual side, another on the buccal side. We assume that the buccal cusp
    is taller that the lingual.
    We're looking for both cusps of this premolar in order to find the "highest one"
    They can also be used to find the fissure inbetweer (see p.9-p.10 in features.pdf)

    To find the buccal cusp of the premolar:

    - We're looking for 2 groups of nested isolines
    - One of them is expected to be "higher"


    This fix was applied to solve the situation where the premolar is not anatomically ideal
    And each one of the "hills" can have more than one nested isoline.
    In that case we need to find the highest nested isoline within a single cusp.

    """
    max_nested_group_ind = 0
    prev_max_nested_group_ind = 0
    if tooth_id in premolar_ids:
        if 'upper' == jaw_type:
            # Search for smallest nested isoline with smallest Y coordinate
            max_y_coord = nested_isoclines[0][-1][0, 1]
            for ind, nested_group in enumerate(nested_isoclines):
                if nested_group[-1][0, 1] > max_y_coord:
                    max_y_coord = nested_group[-1][0, 1]
            min_y_coord = max_y_coord
            prev_min_y_coord = max_y_coord
            for ind, nested_group in enumerate(nested_isoclines):
                if nested_group[-1][0, 1] < min_y_coord:
                    max_nested_group_ind = ind
                    min_y_coord = nested_group[-1][0, 1]
            for ind, nested_group in enumerate(nested_isoclines):
                if nested_group[-1][0, 1] < prev_min_y_coord and\
                        nested_group[-1][0, 1] > min_y_coord:
                    prev_max_nested_group_ind = ind
                    prev_min_y_coord = nested_group[-1][0, 1]
        elif 'lower' == jaw_type:
            # Search for smallest nested isoline with biggest Y coordinate
            min_y_coord = nested_isoclines[0][-1][0, 1]
            for ind, nested_group in enumerate(nested_isoclines):
                if nested_group[-1][0, 1] < min_y_coord:
                    min_y_coord = nested_group[-1][0, 1]
            max_y_coord = min_y_coord
            prev_max_y_coord = min_y_coord
            for ind, nested_group in enumerate(nested_isoclines):
                if nested_group[-1][0, 1] > max_y_coord:
                    max_nested_group_ind = ind
                    max_y_coord = nested_group[-1][0, 1]
            for ind, nested_group in enumerate(nested_isoclines):
                if nested_group[-1][0, 1] > prev_max_y_coord and\
                        nested_group[-1][0, 1] < max_y_coord:
                    prev_max_nested_group_ind = ind
                    prev_max_y_coord = nested_group[-1][0, 1]
    
    # remove isoclines that are in max_nested_group and at the same time in prev_max_nested_group
    if max_nested_group_ind != prev_max_nested_group_ind:
        ind_to_remove = set()
        ind_to_remove_prev = set()
        for i, isocline in enumerate(nested_isoclines[max_nested_group_ind]):
            for j, isocline_prev in enumerate(nested_isoclines[prev_max_nested_group_ind]):
                if isocline.shape == isocline_prev.shape and numpy.all(isocline == isocline_prev):
                    ind_to_remove.add(i)
                    ind_to_remove_prev.add(j)
        new_isoclines = []
        for i, isocline in enumerate(nested_isoclines[max_nested_group_ind]):
            if not i in ind_to_remove:
                new_isoclines.append(isocline)
        nested_isoclines[max_nested_group_ind] = new_isoclines
        new_isoclines = []
        for i, isocline in enumerate(nested_isoclines[prev_max_nested_group_ind]):
            if not i in ind_to_remove:
                new_isoclines.append(isocline)
        nested_isoclines[prev_max_nested_group_ind] = new_isoclines
    """Compute cusp locations

    For each tooth that expects to have cusps we compute cusps using the
    `isoclines_filter.get_hills()` function.
    The fuction returns a list of polygons that expect to contain cusps.
    """
    hills = isoclines_filter.get_hills(
        order=order,
        clusters_num=id_hill_num[tooth_id % 10]
    )
    if not hills:
        log.error("Can't find any hills")
        return result

    result['hill_points'] = get_hill_points(
        mesh,
        [hill[0] for hill in hills],
        [hill[1] for hill in hills],
        order
    )

    # If there's more than one cusp - we're dealing with a tooth that has a fissure
    if id_hill_num[tooth_id % 10] > 1:
        result['fissures'] = get_fissures(
            mesh,
            result['hill_points'],
            order=order
        )

    # Sort nested isolines by length
    nested_group = sorted(
        nested_isoclines,
        key= lambda x: len(x)
    )[-1]

    # Compute cutting edge
    centroid_1 = get_line_centroid(nested_isoclines[max_nested_group_ind][-1])
    centroid_2 = get_line_centroid(nested_isoclines[prev_max_nested_group_ind][-1])

    # When working with a premolar
    # Select the buccal nested isoline group
    if tooth_id in premolar_ids and nested_isoclines[max_nested_group_ind]:
        hill_points = result['hill_points']

        if True: # (old ver) ok
            if tooth_id // 10 in [1, 4] and\
                    get_line_centroid(nested_isoclines[max_nested_group_ind][-1])[0] <\
                    get_line_centroid(nested_isoclines[prev_max_nested_group_ind][-1])[0]:
                # left 
                if len(hill_points) > 1 and\
                        mesh_points[hill_points[0]][0] >= mesh_points[hill_points[1]][0]:
                    hill_points[0], hill_points[1] = hill_points[1], hill_points[0]
                
                result['cutting_edge'] = find_cutting_edge(
                        mesh_points,
                        nested_isoclines[max_nested_group_ind],
                        order=order,
                        use_three_point=True,
                        hill_point=hill_points[0]
                )
            elif tooth_id // 10 in [1, 4]:
                # left
                if len(hill_points) > 1 and\
                        mesh_points[hill_points[0]][0] >= mesh_points[hill_points[1]][0]:
                    hill_points[0], hill_points[1] = hill_points[1], hill_points[0]
                
                result['cutting_edge'] = find_cutting_edge(
                        mesh_points,
                        nested_isoclines[prev_max_nested_group_ind],
                        order=order,
                        use_three_point=True,
                        hill_point=hill_points[0]
                )            
            elif tooth_id // 10 in [2, 3] and\
                    get_line_centroid(nested_isoclines[max_nested_group_ind][-1])[0] >\
                    get_line_centroid(nested_isoclines[prev_max_nested_group_ind][-1])[0]:
                # right
                if len(hill_points) > 1 and\
                        mesh_points[hill_points[0]][0] <= mesh_points[hill_points[1]][0]:
                    hill_points[0], hill_points[1] = hill_points[1], hill_points[0]
                
                result['cutting_edge'] = find_cutting_edge(
                        mesh_points,
                        nested_isoclines[max_nested_group_ind],
                        order=order,
                        use_three_point=True,
                        hill_point=hill_points[0]
                )
            elif tooth_id // 10 in [2, 3]:
                # right
                if len(hill_points) > 1 and\
                        mesh_points[hill_points[0]][0] <= mesh_points[hill_points[1]][0]:
                    hill_points[0], hill_points[1] = hill_points[1], hill_points[0]
                
                result['cutting_edge'] = find_cutting_edge(
                        mesh_points,
                        nested_isoclines[prev_max_nested_group_ind],
                        order=order,
                        use_three_point=True,
                        hill_point=hill_points[0]
                )
        else: # new ver bad
            nested_group_ind = prev_max_nested_group_ind
            # Select the correct group depending on the quadrant the premolar belongs to
            if tooth_id // 10 in [1, 4]: # left

                if len(hill_points) > 1 and\
                        mesh_points[hill_points[0]][0] >= mesh_points[hill_points[1]][0]:
                    hill_points[0], hill_points[1] = hill_points[1], hill_points[0]

                if centroid_1[0] < centroid_2[0]:
                    nested_group_ind = max_nested_group_ind
            elif tooth_id // 10 in [2, 3]: # right

                if len(hill_points) > 1 and\
                        mesh_points[hill_points[0]][0] <= mesh_points[hill_points[1]][0]:
                    hill_points[0], hill_points[1] = hill_points[1], hill_points[0]

                if centroid_1[0] < centroid_2[0]:
                    log.debug('centroid_1[0] < centroid_2[0]')# tmp
                    nested_group_ind = prev_max_nested_group_ind # ??? cur ver
                    #nested_group_ind = max_nested_group_ind #?

            #log.debug(tooth_id)# tmp

            result['cutting_edge'] = find_cutting_edge(
                mesh_points,
                nested_isoclines[nested_group_ind],
                order=order,
                use_three_point=True,
                hill_point=hill_points[0]
            )

    # If the tooth is a incisor (not 4 cusps, not premolar and not a canine)
    elif tooth_id in cutting_edge_ids and 3 != tooth_id % 10:

        # On the lower arch a different method is used
        # Because lower incisors have a more narrow shape
        if tooth_id // 10 in (3, 4):
            result['cutting_edge'] = find_cutting_edge_iso_obb(
                mesh,
                tooth_id,
                isoclines_filter,
            )

        # On the upper arch the same method as with premolars is used
        elif tooth_id // 10 in (1, 2):
            result['cutting_edge'] = find_cutting_edge(
                mesh_points,
                nested_group,
                order=order
            )
            result['hill_points'] = [result['cutting_edge'][
                len(result['cutting_edge']) // 2]]

    # By this time we're only left with a canine
    # We find the cutting edge using the same technique that we used
    # with premolars and upper incisors
    elif tooth_id in cutting_edge_ids:
        result['cutting_edge'] = find_cutting_edge(
            mesh_points,
            nested_group,
            order=order,
            use_three_point=True,
            hill_point=result['hill_points'][0]
        )
    return result


def __extract_single_tooth_features(tooth_ids: List[int],
                                    meshes: List[vtk.vtkPolyData],
                                    isoclines_num: int,
                                    process_num: int,
                                    queue: multiprocessing.Queue) -> None:
    """Extract features from a tooth

    Extract features from a single tooth.

    :param tooth_ids: Tooth ids based on FDI notation system
    :type tooth_ids: List[int]
    :param meshes: List of tooth meshes for each tooth id
    :type meshes: List[vtk.vtkPolyData]
    :param queue: Queue for results data
    :type queue: multiprocessing.Queue
    """

    result = {}
    for tooth_id, mesh in zip(tooth_ids, meshes):
        try:
            result[tooth_id] = __extract_tooth_features_using_isoclines(
                tooth_id,
                isoclines_num,
                mesh
            )
        except:
            """Topology error handling

            In some cases the feature extraction can raise a TopologyError exception.
            In order to overcome this we decimate and smooth the given mesh and attempt to
            perform the same feature extraction procedure again.
            """

            log.info('Topology error:Re extract features')

            ITER_NUM = 2 # 2 org #4
            RELAXATION_FACTOR = 0.1 # 0.01 ?
            OUT_POLY_COEF = 0.8

            mesh = preprocess_mesh(mesh, log, ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF)

            result[tooth_id] = __extract_tooth_features_using_isoclines(
                tooth_id,
                isoclines_num,
                mesh
            )
    queue.put(result)
    if 0 != process_num and not sys.platform.startswith('win'):
        queue.close()


def extract_features(id_mesh_dict: List[Dict[int, vtk.vtkPolyData]],
                     isoclines_num: int,
                     process_num=2) -> Dict:
    """Extract features

    Lauches multiprocess extraction of features on a given arch.

    :param id_mesh_dict: List of teeth as VTK objects
    :type id_mesh_dict: List[Dict[int, vtk.vtkPolyData]]
    :param process_num: Number of processes to run in parallel, defaults to 2
    :type process_num: number, optional
    :returns: Dictionary with tooth features
    :rtype: {Dict}
    """
    features_dict = {}

    # Start multiple processes of feature extration for a single tooth
    queue = multiprocessing.Queue()
    if 0 == process_num or sys.platform.startswith('win'):
        # solve error 'can't pickle vtkData objects' (windows)
        __extract_single_tooth_features(
            list(id_mesh_dict.keys()),
            [val['mesh'] for val in id_mesh_dict.values()],
            isoclines_num,
            process_num,
            queue
        )
        result = queue.get()
        for tooth_id in result.keys():
           features_dict[tooth_id] = result[tooth_id]
    else:
        # Split incoming data into chunks
        tooth_ids = list(chunks_generator(list(id_mesh_dict.keys()), len(id_mesh_dict) // process_num + 1))
        meshes = [[id_mesh_dict[tooth_id]['mesh'] for tooth_id in chunk] for chunk in tooth_ids]
        processes = []
        for i in range(process_num):
            log.debug(f'proc {i+1}: tooth_ids: len={len(tooth_ids[i])} {tooth_ids[i]}, isoclines_num {isoclines_num}')
            process = multiprocessing.Process(
                target=__extract_single_tooth_features,
                args=(
                    tooth_ids[i],
                    meshes[i],
                    isoclines_num,
                    process_num,
                    queue
                )
            )
            processes.append(process)
            process.start()
        for i in range(process_num):
            result = queue.get()
            for tooth_id in result.keys():
                features_dict[tooth_id] = result[tooth_id]
        for process in processes:
            process.join()
    return features_dict


def visualize_features(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                       features_dict: Dict,
                       wisdom_teeth_curve_dict: Dict,
                       jaw_type: str) -> None:
    """Visualise features

    Render tooth features with VTK library.

    :param id_mesh_dict: Dictionary with loded mesh as returned by mesh_io
    :type id_mesh_dict: Dict[int, vtk.vtkPolyData]
    :param features_dict: Dictionary with loaded features
    :type features_dict: Dict
    :param wisdom_teeth_curve_dict: Dictionary with dental arch visualisation (connects cusps on molars)
    :type wisdom_teeth_curve_dict: Dict
    :param jaw_type: Either "lower" or "upper"
    :type jaw_type: str
    """
    shift = 0.0  # shift points for better visibility
    upper_id = tuple(range(18, 10, -1)) + tuple(range(21, 29))
    lower_id = tuple(range(48, 40, -1)) + tuple(range(31, 39))
    ids = []
    if 'upper' == jaw_type:
        shift = -0.1
        ids = upper_id
    elif 'lower' == jaw_type:
        shift = 0.1
        ids = lower_id
    else:
        log.error('Unknown jaw type')
        return None

    # Init renderer
    renderer = vtk.vtkRenderer()
    for tooth_id in list_intersection(id_mesh_dict.keys(), ids):

        # Check if tooth_id in id_mesh_dict
        mesh = id_mesh_dict[tooth_id]['mesh']
        mesh_points = numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())

        # Visualise fissures
        for fissure in features_dict[tooth_id]['fissures']:
            if fissure:
                vtk_fissure_points = vtk.vtkPoints()
                fissure_lines = vtk.vtkCellArray()
                fissure_pd = vtk.vtkPolyData()
                fissure_pd.SetPoints(vtk_fissure_points)
                fissure_pd.SetLines(fissure_lines)
                prev_point_id = vtk_fissure_points.InsertNextPoint(
                    mesh_points[fissure[0]][0],
                    mesh_points[fissure[0]][1] + shift,
                    mesh_points[fissure[0]][2]
                )
                for point in fissure[1:]:
                    current_point_id = vtk_fissure_points.InsertNextPoint(
                        mesh_points[point][0],
                        mesh_points[point][1] + shift,
                        mesh_points[point][2]
                    )
                    line = vtk.vtkLine()
                    line.GetPointIds().SetId(0, prev_point_id)
                    line.GetPointIds().SetId(1, current_point_id)
                    fissure_lines.InsertNextCell(line)
                    prev_point_id = current_point_id
                fissure_points_mapper = vtk.vtkPolyDataMapper()
                fissure_points_mapper.SetInputData(fissure_pd)
                fissure_points_actor = vtk.vtkActor()
                fissure_points_actor.GetProperty().SetColor(1.0, 0.0, 0.0)
                fissure_points_actor.SetMapper(fissure_points_mapper)
                fissure_points_actor.GetProperty().SetLineWidth(5)
                renderer.AddActor(fissure_points_actor)

        # Visualise cutting egdes
        cutting_edge = features_dict[tooth_id]['cutting_edge']
        if cutting_edge:
            vtk_cutting_edge_points = vtk.vtkPoints()
            cutting_edge_lines = vtk.vtkCellArray()
            cutting_edge_pd = vtk.vtkPolyData()
            cutting_edge_pd.SetPoints(vtk_cutting_edge_points)
            cutting_edge_pd.SetLines(cutting_edge_lines)
            prev_point_id = vtk_cutting_edge_points.InsertNextPoint(
                mesh_points[cutting_edge[0]][0],
                mesh_points[cutting_edge[0]][1] + shift,
                mesh_points[cutting_edge[0]][2]
            )
            for point in cutting_edge[1:]:
                current_point_id = vtk_cutting_edge_points.InsertNextPoint(
                    mesh_points[point][0],
                    mesh_points[point][1] + shift,
                    mesh_points[point][2]
                )
                line = vtk.vtkLine()
                line.GetPointIds().SetId(0, prev_point_id)
                line.GetPointIds().SetId(1, current_point_id)
                cutting_edge_lines.InsertNextCell(line)
                prev_point_id = current_point_id
            cutting_edge_points_mapper = vtk.vtkPolyDataMapper()
            cutting_edge_points_mapper.SetInputData(cutting_edge_pd)
            cutting_edge_points_actor = vtk.vtkActor()
            cutting_edge_points_actor.GetProperty().SetColor(0.0, 1.0, 0.0)
            cutting_edge_points_actor.SetMapper(cutting_edge_points_mapper)
            cutting_edge_points_actor.GetProperty().SetLineWidth(5)
            renderer.AddActor(cutting_edge_points_actor)

        # Visualise cusps
        vtk_hill_points = vtk.vtkPoints()
        hill_vertices = vtk.vtkCellArray()
        hill_pd = vtk.vtkPolyData()
        hill_pd.SetPoints(vtk_hill_points)
        hill_pd.SetVerts(hill_vertices)
        hill_points = features_dict[tooth_id]['hill_points']
        for point in hill_points:
            point = mesh_points[point]
            point_id = vtk_hill_points.InsertNextPoint(*point)
            hill_vertices.InsertNextCell(1, [point_id])
        hill_points_mapper = vtk.vtkPolyDataMapper()
        hill_points_mapper.SetInputData(hill_pd)
        hill_points_actor = vtk.vtkActor()
        hill_points_actor.GetProperty().SetColor(0.0, 0.0, 1.0)
        hill_points_actor.SetMapper(hill_points_mapper)
        hill_points_actor.GetProperty().SetPointSize(10)
        renderer.AddActor(hill_points_actor)

        input_mapper = vtk.vtkPolyDataMapper()
        input_mapper.SetInputData(mesh)
        input_actor = vtk.vtkActor()
        input_actor.GetProperty().SetColor(0.9, 0.9, 0.9)
        input_actor.SetMapper(input_mapper)
        input_actor.GetProperty().SetOpacity(0.9)
        renderer.AddActor(input_actor)

    # Plot lines that connect cusps on molars
    for curve_range in (
            list_intersection(ids[:5], id_mesh_dict.keys()),
            list_intersection(ids[len(ids) - 5: ], id_mesh_dict.keys())):
        vtk_curve_points = vtk.vtkPoints()
        curve_lines = vtk.vtkCellArray()
        curve_pd = vtk.vtkPolyData()
        curve_pd.SetPoints(vtk_curve_points)
        curve_pd.SetLines(curve_lines)
        prev_point_id = 0
        for tooth_id in curve_range:
            mesh_points = numpy_support.vtk_to_numpy(
                id_mesh_dict[tooth_id]['mesh'].GetPoints().GetData()
            )
            points = wisdom_teeth_curve_dict[tooth_id]
            for point in points:
                current_point_id = vtk_curve_points.InsertNextPoint(
                    mesh_points[point][0],
                    mesh_points[point][1] + shift,
                    mesh_points[point][2]
                )
                line = vtk.vtkLine()
                line.GetPointIds().SetId(0, prev_point_id)
                line.GetPointIds().SetId(1, current_point_id)
                curve_lines.InsertNextCell(line)
                prev_point_id = current_point_id

        curve_points_mapper = vtk.vtkPolyDataMapper()
        curve_points_mapper.SetInputData(curve_pd)
        curve_points_actor = vtk.vtkActor()
        curve_points_actor.GetProperty().SetColor(1.0, 1.0, 0.0)
        curve_points_actor.SetMapper(curve_points_mapper)
        curve_points_actor.GetProperty().SetLineWidth(5)
        renderer.AddActor(curve_points_actor)

    render_window = vtk.vtkRenderWindow()
    render_window.AddRenderer(renderer)
    render_window.SetSize(1024, 1080)  # TODO:

    interactor = vtk.vtkRenderWindowInteractor()
    interactor.SetRenderWindow(render_window)
    renderer.SetBackground(0.1, 0.2, 0.3)
    render_window.Render()
    interactor.Start()


def ExtractFeatures():
    parser = OptionParser()
    parser.add_option("-s", "--session", 
                    action="store",
                    dest="session_filename",
                    help="set session file path name",
                    metavar="FILE")
    parser.add_option("-c", "--config", 
                    action="store",
                    dest="config_filename",
                    help="set config file path name",
                    metavar="FILE")
    parser.add_option("-v", "--vis",
                    action="store",
                    dest="jaw_type",
                    default=None,
                    help="features visualization: where jaw_type is one of ['lower', 'upper']")
    parser.add_option("-r", "--recalc",
                    action="store_true",
                    dest="recalculate",
                    help="features: to recalculate new...")
    parser.add_option("-q", "--quiet",
                    action="store",
                    dest="verbose",
                    default=1,
                    type='int',
                    help="set log 0=get environ LOG_LEVEL, 1=DEBUG, 2, 3, 4, 5=FATAL [default: 1]")
    
    (options, args) = parser.parse_args()
    
    level = logging.INFO
    if 0 != options.verbose :
        levels = { 
            1 : logging.DEBUG,
            2 : logging.INFO,
            3 : logging.WARNING,
            4 : logging.ERROR,
            5 : logging.FATAL
        }
        if options.verbose > 0 and options.verbose <= 5 : 
            level = levels[options.verbose]
    else:
        level = logging.getLevelName(os.environ.get('LOG_LEVEL', 'INFO'))

    log.setLevel(level=level)
    log.info(f'log level: {logging.getLevelName(level)}')

    #log.debug(f' : {options} : {args}')

    # Read session configuration
    directory = Path(getframeinfo(currentframe()).filename).resolve().parents[0]

    session_filename = options.session_filename
    if not session_filename:
        session_filename = directory / 'session.json'
    log.info(f'session filename : {session_filename}')

    session_config_data = json.load(open(session_filename, 'rt'))

    config_filename = options.config_filename 
    if not config_filename:
        config_filename = session_config_data['paths']['file_config'] 
    if not os.path.isabs(config_filename):
        config_filename = os.path.normpath(directory / config_filename)
    log.info(f'config filename : {config_filename}')

    config_data = json.load(open(config_filename, 'rt'))
    config_data = config_data['features']
    case_id = session_config_data['hash_for_patient_tag']
    
    # directory_out = os.path.join(session_config_data['paths']['dir_out'], case_id)
    directory_out = session_config_data['paths']['dir_out']
    if not os.path.isabs(directory_out):
        directory_out = os.path.normpath(directory / directory_out) 
    if not os.path.exists(directory_out):
        try:
            os.makedirs(directory_out, exist_ok=True)
        except OSError as exception:
            log.error(f'output directory : {directory_out} not create')
            sys.exit(2)
    log.info(f'out directory : {directory_out}')

    upper_model_path = session_config_data['paths']['file_u']
    if not os.path.isabs(upper_model_path):
        upper_model_path = os.path.normpath(directory / upper_model_path) 
    log.info(f'file upper : {upper_model_path}')

    lower_model_path = session_config_data['paths']['file_l']
    if not os.path.isabs(lower_model_path):
        lower_model_path = os.path.normpath(directory / lower_model_path) 
    log.info(f'file lower : {lower_model_path}')   

    log.info(f'hash_for_patient_tag : {case_id}')

    missing_id = session_config_data['missing_id']
    log.info(f'missing_id : {missing_id}')

    isoclines_num = 400
    if "isoclines_num" in config_data:
        isoclines_num = config_data['isoclines_num']
        log.info(f'isoclines_num : {isoclines_num}')
    else:
        log.info(f'isoclines_num not def, set default: {isoclines_num}')

    process_num = 2
    if "process_num" in config_data:
        process_num = config_data['process_num']
        log.info(f'process_num : {process_num}')
    else:
        log.info(f'process_num not def, set default: {process_num}')

    # Setup variables, read classified crowns and exclude wisdom teeth from work data
    upper_id = tuple(range(11, 19)) + tuple(range(21, 29))
    lower_id = tuple(range(41, 49)) + tuple(range(31, 39))
    
    id_mesh_dict = read_obj_teeth(os.path.join(directory_out, f'{case_id}_teeth.obj'))
    id_mesh_dict = {key: {'mesh': value} for key, value in id_mesh_dict.items()
        if not (key in [18, 28, 38, 48])}

    old_points = {}
    for key, val in id_mesh_dict.items():
        mesh = val['mesh']
        if key % 10 < 5: # If tooth in frontal group (not in molars)
            print(f"------------------------- Processing {key} tooth-----------------------")
            log.info(key)
            symmetry_axis = None
            if key % 10 in (1, 2, 3):
                symmetry_axis = get_symmetry_axis(mesh, key)
            elif key % 10 in (4, 5, 6):
                symmetry_axis = get_symmetry_axis_circle_projection(mesh, key)
            rotation_matrix = None

            # Rotate crown to local coordinate system (so that symetry axis is Z axis)
            # This is required for feature extraction to work with teeth from diferent quadrants
            if key // 10 in (1, 2):
                symmetry_angle = angle(symmetry_axis, numpy.array((0.0, 1.0, .0)))
                if symmetry_angle > math.pi / 2:
                    symmetry_axis = -numpy.asarray(symmetry_axis)
                rotation_matrix = rotation( numpy.asarray(symmetry_axis), numpy.array((0.0, 1.0, .0)) )
            else:
                symmetry_angle = angle(symmetry_axis, numpy.array((0.0, -1.0, .0)))
                if symmetry_angle > math.pi / 2:
                     symmetry_axis = -numpy.asarray(symmetry_axis)
                rotation_matrix = rotation(numpy.asarray(symmetry_axis), numpy.array((0.0, -1.0, .0)))

            # Apply rotation that was computed in the previous code block
            centroid = get_centroid(mesh)
            mesh_points = vtk.util.numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
            old_points[key] = mesh_points
            new_points = rotation_matrix.dot((mesh_points - centroid).T).T + centroid
            mesh.GetPoints().SetData(vtk.util.numpy_support.numpy_to_vtk(new_points))

    # Start extracting features
    features_dict = {}
    log.info('Extracting features...')
    features_dict = extract_features(id_mesh_dict, isoclines_num, process_num=process_num)

    log.debug(f'old_points len {len(old_points)}')
    if len(old_points):
        log.debug('restore old_points')
        for key, val in id_mesh_dict.items():
            mesh = val['mesh']
            if key % 10 < 5:
                mesh.GetPoints().SetData(vtk.util.numpy_support.numpy_to_vtk(old_points[key]))

    isoclines_dict = {}
    for key in features_dict:
         if 'isoclines' in features_dict[key]:
            isoclines_dict[key] = features_dict[key]['isoclines']
            features_dict[key].pop('isoclines')

    # Save extracted features
    log.info('Save extracted features...')
    save_features(
    os.path.join(directory_out, f'features_{case_id}.json'), id_mesh_dict, features_dict)
            
    # Write isolines to OBJ file (used only for visual evaluation)
    with open(os.path.join(directory_out, f'isoclines_{case_id}.obj'), 'wt') as outfile:
        for key, isoclines in isoclines_dict.items():
            jaw_type = 'lower'
            if key // 10 in (1, 2):
                jaw_type = 'upper'
            outfile.write('g {}{}\n'.format(jaw_type[0], key))
            for ind, line in enumerate(isoclines):
                outfile.write('o {}\n'.format(ind))
                for point in line:
                    outfile.write(' '.join(['v', str(point[0]), str(point[1]), str(point[2])]) + '\n' )


def IsoclinesFilter_Test():
        
    id_mesh_dict = read_obj_teeth("/home/andtokm/Projects/data/cases/2878/automodeling/out/2878_teeth.obj")
    # id_mesh_dict = read_obj_teeth("/home/andtokm/Projects/data/cases/2878/automodeling/out/2878_teeth.obj")

    #print(id_mesh_dict)


    id_mesh_dict = {key: {'mesh': value} for key, value in id_mesh_dict.items()
        if not (key in [18, 28, 38, 48])}

    mesh = id_mesh_dict.get(21)['mesh']
 
    ITER_NUM = 2 # 2 org #4
    RELAXATION_FACTOR = 0.1 # 0.01 ?
    OUT_POLY_COEF = 0.8
    isoclines_num = 400
    normal = [0.0, 1.0, 0.0]

    mesh = preprocess_mesh(mesh, log, ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF)

    isoclines_filter = IsoclinesFilter(mesh, isoclines_num=isoclines_num,normal=normal)

    # isoclines = isoclines_filter.get_isoclines()
    isoclines_filter.visualize_isoclines()


    # print(isoclines);


if __name__ == '__main__':
    # ExtractFeatures()

    IsoclinesFilter_Test();