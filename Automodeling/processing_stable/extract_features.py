import json
import logging
import math
import multiprocessing
import os
import os.path
import datetime
import sys
import warnings
from typing import Dict, List

import numpy as np
import vtk
from shapely import ops
from shapely.geometry import (LineString, MultiPoint, MultiPolygon, Point,
                              Polygon)
from vtk.util import numpy_support

from isoclines import IsoclinesFilter

from utils import (chunks_generator, dist, get_line_centroid,
                   line_most_remote_points, lines_similarity_measure,
                   list_intersection, rotation, vector_l2_norm, preprocess_mesh)


warnings.simplefilter(action='ignore', category=FutureWarning)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('features_extraction')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

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
            polygon_points = np.asarray(hill.exterior.coords.xy)
            point = np.asarray([polygon_points[0, 0], z_coord, polygon_points[1, 0]])
            hill_points.append(int(np.square(points - point).sum(axis=1).argmin()))
            continue

        # Collect point indexes for each fond point within the point scope of the mesh model
        tmp_ind = (points[:, [0, 2]] == geoms[0]).sum(axis=1).astype(bool)
        for i in range(1, len(geoms)):
            tmp_ind = np.logical_or(
                tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
        index_arr = np.argwhere(tmp_ind)[0]
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
        norm_vec_1 = np.asarray([dircet_vec_1[1], -dircet_vec_1[0]])
        dircet_vec_2 = mean_points[3, [0, 2]] - mean_points[1, [0, 2]]
        dircet_vec_2 /= vector_l2_norm(dircet_vec_2)
        norm_vec_2 = np.asarray([dircet_vec_2[1], -dircet_vec_2[0]])

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
                tmp_ind = np.logical_or(
                        tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
            index_arr = np.argwhere(tmp_ind)[0]
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
                tmp_ind = np.logical_or(
                        tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
            index_arr = np.argwhere(tmp_ind)[0]
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
        dircet_vec = np.asarray([norm_vec[1], -norm_vec[0]])
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
            tmp_ind = (points[:, [0, 2]] == geoms[0]).sum(axis=1) == 2
            for i in range(1, len(geoms)):
                tmp_ind = np.logical_or(
                        tmp_ind, (points[:, [0, 2]] == geoms[i]).sum(axis=1) == 2)
            index_arr = np.argwhere(tmp_ind)[0]
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
        mesh_points: np.ndarray,
        nested_isoclines: List[np.ndarray],
        order: str,
        use_three_point: bool=False,
        hill_point: int=None) -> List[int]:
    """Find cutting edge

    Find cutting edge on non-molar teeth.

    :param mesh_points: Mesh points as an (N,3) np.ndarray
    :type mesh_points: np.ndarray
    :param nested_isoclines: List of (M,3) ndarrays representing isolines
    :type nested_isoclines: List[np.ndarray]
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
    similarities = np.zeros((len(nested_isoclines) - 1, ))
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
        cutting_edge = np.zeros((cutting_edge_len, 3))
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
        cutting_edge = np.zeros((POINTS_NUM, 3))
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
        cutting_edge_list.append(int(np.square(mesh_points - cutting_edge[i]).sum(axis=1).argmin()))
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
        if not math.isclose(np.linalg.norm(mid_axis), 0.0) and not math.isclose(np.linalg.norm(mid_axis), 0.0):
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
                np.linalg.norm(mid_axis) * np.linalg.norm(max_axis),
                min(np.linalg.norm(mid_axis), np.linalg.norm(max_axis))\
                    / max(np.linalg.norm(mid_axis), np.linalg.norm(max_axis))
            ])

    # Filter OBB structure based on area and relation of the OBB sides
    lines = new_lines
    idx = 0
    # We're moving from top to bottom and looking for small and narow OBBs
    while idx < len(obbs) and (obbs[idx][3] < 10.0 or obbs[idx][4] < 0.6):
        # When we find one that satisfies the condition - count them
        idx += 1

    # We take the midpoints of the narow sides of found OBBs
    cutting_edge = np.zeros((idx * 2, 3))
    for i in range(idx):
        corner = np.asarray(obbs[i][0])
        mid_axis = np.asarray(obbs[i][1])
        max_axis = np.asarray(obbs[i][2])
        cutting_edge[idx - i - 1] = corner + mid_axis / 2
        cutting_edge[idx + i] = corner + max_axis + mid_axis / 2

    # And search for closest points on the model to build tha cutting edge of the crown
    cutting_edge = cutting_edge[cutting_edge[:, 0].argsort()]
    cutting_edge_list = []
    for i in range(cutting_edge.shape[0]):
        cutting_edge_list.append(int(np.square(mesh_points - cutting_edge[i]).sum(axis=1).argmin()))
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
                if isocline.shape == isocline_prev.shape and np.all(isocline == isocline_prev):
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


def __extract_single_tooth_features(
        tooth_ids: List[int],
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


def extract_features(
        id_mesh_dict: List[Dict[int, vtk.vtkPolyData]],
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
        print(f" **** process_num = {process_num}")
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


def visualize_features(
        id_mesh_dict: Dict[int, vtk.vtkPolyData],
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


if __name__ == '__main__':

    from math import pi
    from pathlib import Path
    from inspect import currentframe, getframeinfo
    from optparse import OptionParser
    from teeth_movement.teeth_curve import find_wisdom_teeth_curves_dict
    from teeth_movement.utils import separate_connected_components, save_features, load_features, angle, get_centroid, rotation
    from teeth_movement.mesh_io import read_obj_teeth
    from teeth_movement.symmetry import get_symmetry_axis, get_symmetry_axis_circle_projection
    from teeth_movement.classification import classify_teeth
    from teeth_movement.mesh_io import read_stl

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
    # print("{0}: id_mesh_dict {1}".format(datetime.date.today(), id_mesh_dict))

    id_mesh_dict = {key: {'mesh': value} for key, value in id_mesh_dict.items()
        if not (key in [18, 28, 38, 48])}
    # print("{0}: id_mesh_dict {1}".format(datetime.date.today(), id_mesh_dict))

    """
    for k, v in id_mesh_dict.items():
        print("======================== Tooth {0} ========================".format(k))
        polyData: vtk.vtkPolyData = v.get("mesh")
        polyes = polyData.GetPolys();
        print(polyData)
        print("====================")
        print(polyes)
    """

    # sys.exit(0)

    # If the script is run to build visualisation
    if options.jaw_type:
        log.info(f'Load features_{case_id}.json...')
        features_dict = {}

        # Read JSON file with saved features
        if os.path.isfile(os.path.join(directory_out, f'features_{case_id}.json')):
            features_dict = load_features(
                os.path.join(directory_out, f'features_{case_id}.json'),
                id_mesh_dict
            )
            wisdom_teeth_curves_dict = find_wisdom_teeth_curves_dict(
                id_mesh_dict,
                features_dict
            )

            # print("{0}: Visualise features".format(datetime.date.today()))
            # And visualise features
            visualize_features(
                id_mesh_dict,
                features_dict,
                wisdom_teeth_curves_dict,
                jaw_type=options.jaw_type
            )
        else:
            log.warning('Features file not found')
    else:
        # Create blank dictionary for tooth features
        features_dict = {}
        print("{0}: CREATING BLANK".format(datetime.date.today()))
        if options.recalculate or not os.path.isfile(os.path.join(directory_out, f'features_{case_id}.json')):
            # Start computing tooth symmetry axes
            log.info('Estimating symmetry axes...')
            old_points = {}
            for key, val in id_mesh_dict.items():
                # print("{0}: Compute tooth [{1} : {2}]".format(datetime.date.today(), key, val))
                mesh = val['mesh']
                print(f"------------------------- Processing {key} tooth-----------------------")
                # If tooth in frontal group (not in molars)
                if key % 10 < 7:
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
                        symmetry_angle = angle(symmetry_axis, np.array((0.0, 1.0, .0)))
                        if symmetry_angle > pi / 2:
                            symmetry_axis = -np.asarray(symmetry_axis)
                        rotation_matrix = rotation(
                            np.asarray(symmetry_axis),
                            np.array((0.0, 1.0, .0))
                        )
                    else:
                        symmetry_angle = angle(symmetry_axis, np.array((0.0, -1.0, .0)))
                        if symmetry_angle > pi / 2:
                            symmetry_axis = -np.asarray(symmetry_axis)
                        rotation_matrix = rotation(
                            np.asarray(symmetry_axis),
                            np.array((0.0, -1.0, .0))
                        )
                    # Apply rotation that was computed in the previous code block
                    centroid = get_centroid(mesh)
                    mesh_points = vtk.util.numpy_support.vtk_to_numpy(
                        mesh.GetPoints().GetData()
                    )
                    old_points[key] = mesh_points
                    new_points = rotation_matrix.dot((mesh_points - centroid).T).T + centroid
                    mesh.GetPoints().SetData(vtk.util.numpy_support.numpy_to_vtk(new_points))

            # Start extracting features
            log.info('Extracting features...')
            features_dict = extract_features(id_mesh_dict,
                                             isoclines_num,
                                             process_num=process_num)

            log.debug(f'old_points len {len(old_points)}')
            if len(old_points):
                log.debug('restore old_points')
                for key, val in id_mesh_dict.items():
                    mesh = val['mesh']
                    if key % 10 < 5:
                        mesh.GetPoints().SetData(
                            vtk.util.numpy_support.numpy_to_vtk(old_points[key])
                        )

            isoclines_dict = {}
            for key in features_dict:
                if 'isoclines' in features_dict[key]:
                    isoclines_dict[key] = features_dict[key]['isoclines']
                    features_dict[key].pop('isoclines')

            # Save extracted features
            log.info('Save extracted features...')
            save_features(
                os.path.join(directory_out, f'features_{case_id}.json'),
                id_mesh_dict,
                features_dict
            )
            
            # Write isolines to OBJ file (used only for visual evaluation)
            with open(
                    os.path.join(directory_out,
                    f'isoclines_{case_id}.obj'), 'wt') as outfile:
                for key, isoclines in isoclines_dict.items():
                    jaw_type = 'lower'
                    if key // 10 in (1, 2):
                        jaw_type = 'upper'
                    outfile.write('g {}{}\n'.format(jaw_type[0], key))
                    for ind, line in enumerate(isoclines):
                        outfile.write('o {}\n'.format(ind))
                        for point in line:
                            outfile.write(' '.join([
                                'v',
                                str(point[0]),
                                str(point[1]),
                                str(point[2])]) + '\n'
                            )
        else:
            log.error(f'features_{case_id}.json is exist, exit...')
