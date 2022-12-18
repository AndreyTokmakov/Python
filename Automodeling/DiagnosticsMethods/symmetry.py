import json
import logging
import os
import sys
import warnings
from math import cos, pi, sin
from typing import Dict, Tuple, List

import numpy as np
import vtk
# import datetime
from scipy import optimize
from scipy.spatial import ConvexHull
from vtk.util import numpy_support

from isoclines import IsoclinesFilter
from mesh_io import read_obj_teeth
from utils import (angle, get_centroid, get_line_centroid, get_rotation_matrix, load_features, rotation, vector_l2_norm,
                   dist_to_circle_sum, calc_R, f_2)

warnings.simplefilter(action='ignore', category=FutureWarning)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('symmetry')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'


def get_symmetry_axis_circle_projection(
        mesh: vtk.vtkPolyData,
        tooth_id: int) -> List[int]:  # np.ndarray:
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
    :returns: Vertical symmetry axis as np.ndarray
    :rtype: {np.ndarray}
    """

    ANGLE_NUM = 50  # 100 old!!
    initial_vector = np.asarray([1.0, 0.0])
    rotation_values = np.linspace(-45.0, 45.0, 45)  # np.linspace(-45.0, 45.0, 90) old
    dists, angles, rotation_angles = [], [], []
    centroid = get_centroid(mesh)
    points = numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    polys_data = numpy_support.vtk_to_numpy(mesh.GetPolys().GetData())
    polys_data = polys_data.reshape(polys_data.shape[0] // 4, 4)[..., 1:].flatten()
    indexes = np.unique(polys_data)
    points = points[indexes] - centroid

    # Start fitting iterations
    for i in range(ANGLE_NUM):
        angle = 360 / ANGLE_NUM * i
        angle_rad = float(angle) * pi / 180
        rotation_matrix = np.asarray([[cos(angle_rad), -sin(angle_rad)],
                                      [sin(angle_rad), cos(angle_rad)]])
        # Apply first rotation (Y axis)
        rotation_axis = rotation_matrix.dot(initial_vector)
        # print(f"   angle: [{i}, {angle_rad}], Axis:  {rotation_axis}")
        for j in range(rotation_values.shape[0]):
            angles.append(angle)
            rotation_angles.append(rotation_values[j])
            rotation_matrix = get_rotation_matrix(np.asarray((rotation_axis[0], 0, rotation_axis[1])),
                                                  rotation_values[j] * pi / 180)
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

    rotation_matrix = np.asarray([[cos(angle_rad), -sin(angle_rad)], [sin(angle_rad), cos(angle_rad)]])
    rotation_axis = rotation_matrix.dot(initial_vector).tolist()
    rotation_matrix = get_rotation_matrix(np.asarray((rotation_axis[0], 0, rotation_axis[1])), -angle_rad)
    # Compute vertical symmetry axis
    symmetry_axis = rotation_matrix.dot(np.asarray((0.0, 1.0, 0.0)).T).T

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
                      cutting_edge=None) -> List[int]:  # np.ndarray:
    """Get symmetry axis

    Compute symmetry axes using isolines

    :param mesh: Input tooth mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param tooth_id: Tooth id as FDI label
    :type tooth_id: int
    :param hill_point: Cusp index, defaults to 0
    :type hill_point: number, optional
    :param cutting_edge: Edge polyline points index, defaults to None
    :type cutting_edge: np.ndarray, optional
    :returns: List of 3 floats [float, float, float]
    :rtype: {List}
    """
    ISOCLINE_NUM = 100  # todo new

    # Compute 100 isolines for given mesh
    isoclines_filter = IsoclinesFilter(mesh, isoclines_num=ISOCLINE_NUM)
    lines = isoclines_filter.get_isoclines()

    # Find longest closed isoline
    max_line_len = max(map(lambda x: x.shape[0], lines))
    lines_np = np.zeros((len(lines), max_line_len, 3))
    for i, line in enumerate(lines):
        lines_np[i, :line.shape[0], :] = line
    # Group isolined sorted by Z coords
    unique_z_coords = np.unique(lines_np[..., 1])
    new_lines = []
    for z_coord in unique_z_coords:
        if 1 == np.count_nonzero(lines_np[:, 0, 1] == z_coord):
            new_line = lines_np[lines_np[:, 0, 1] == z_coord][0]
            new_line = new_line[new_line != np.asarray((.0, .0, .0))]
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
    mesh_points = vtk.util.numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
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


def get_angulation_axis(mesh: vtk.vtkPolyData,
                        cutting_edge: np.ndarray,
                        symmetry_axis: List[int],  # np.ndarray,
                        jaw_type: str,
                        tooth_id: int) -> Tuple[List[int], List[int]]:  # Tuple[np.ndarray, np.ndarray]:
    """Compute angulation axis

    Compute angulation axis for a given crown.

    :param mesh: Crown mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param cutting_edge: Crown cutting edge as point (N,3) array
    :type cutting_edge: np.ndarray
    :param symmetry_axis: Axis as (3,) array
    :type symmetry_axis: np.ndarray
    :param jaw_type: "upper" or "lower" flag indicating jaw type
    :type jaw_type: str
    :type tooth_id: int
    :returns: Origin as (3,) array and axis as (3,) array
    :rtype: {Tuple[np.ndarray, np.ndarray]}
    """

    # Load, convert mesh data adn compute centroid
    mesh_points = vtk.util.numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    polys_data = numpy_support.vtk_to_numpy(mesh.GetPolys().GetData())
    polys_data = polys_data.reshape(polys_data.shape[0] // 4, 4)[..., 1:].flatten()
    indexes = np.unique(polys_data)
    mesh_points = mesh_points[indexes]
    centroid = get_centroid(mesh)

    # Project cutting edge onto a plane that's defines with the symmetry axis as a normal
    mean_point = np.zeros((3,))

    symmetry_axis = np.asarray(symmetry_axis)
    projection_points = centroid + (cutting_edge - centroid).dot(symmetry_axis.T).reshape((
        cutting_edge.shape[0], 1)).dot(symmetry_axis.reshape((1, 3)))

    mean_point = projection_points.mean(axis=0)
    projection_points = cutting_edge - \
                        (cutting_edge - mean_point).dot(symmetry_axis.T).reshape((
                            cutting_edge.shape[0], 1)).dot(symmetry_axis.reshape((1, 3)))
    # Using least square method fit a line to projected points
    datamean = projection_points.mean(axis=0)
    _, _, vv = np.linalg.svd(projection_points - datamean)

    # Look for the point that will be the angulation axis origin
    # By projecting the mesh points to line defined by symmetry axis
    mesh_projection_points = centroid + (mesh_points - centroid).dot(symmetry_axis.T).reshape((
        mesh_points.shape[0], 1)).dot(symmetry_axis.reshape((1, 3)))

    # Depending on the jaw type pick point with max or min
    if 'upper' == jaw_type:
        min_point = mesh_projection_points[mesh_projection_points[:, 1].argmax()]
    elif 'lower' == jaw_type:
        min_point = mesh_projection_points[mesh_projection_points[:, 1].argmin()]
    else:
        raise ValueError('Unknown jaw type')

    angulation_axis = vv[0]
    # if we deal with incisors and canine
    if tooth_id % 10 < 4:
        # orient based on X coordinate sign
        if angulation_axis[0] < 0:
            angulation_axis = -angulation_axis
    # if we deal with premolar
    else:
        # orient angulation axis based on arch type (lower or upper) and Y coordinate sign
        if tooth_id // 10 in (2, 3) and angulation_axis[2] > 0:
            angulation_axis = -angulation_axis
        elif tooth_id // 10 in (1, 4) and angulation_axis[2] < 0:
            angulation_axis = -angulation_axis

    return min_point.tolist(), angulation_axis.tolist()


def find_contact_points(mesh: vtk.vtkPolyData,
                        tooth_id: int,
                        angulation_axis: np.ndarray,
                        origin: np.ndarray,
                        symmetry_axis,
                        jaw_type: str) -> Tuple[List[int], List[int]]:  # np.ndarray:
    """Compute contact points

    Compute contact points for a given crown.

    :param mesh: Crown mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param tooth_id: Tooth if in FDI notation
    :type tooth_id: int
    :param angulation_axis: angulation axis as (3,) array
    :type angulation_axis: np.ndarray
    :param origin: Origin as (3,) array
    :type origin: np.ndarray (3,)
    :param symmetry_axis: symmetry axis as (3,) array
    :type symmetry_axis: np.ndarray
    :param jaw_type: "upper" or "lower" flag indicating jaw type
    :type jaw_type: str
    :returns: contact points (2, 3)
    :rtype: {np.ndarray}
    """

    print(f" find_contact_points ==================== tooth_id = {tooth_id} =============")
    # print("{0}: find_contact_points() entered".format(datetime.date.today()))
    # get mesh points
    mesh_points = vtk.util.numpy_support.vtk_to_numpy(mesh.GetPoints().GetData())
    polys_data = numpy_support.vtk_to_numpy(mesh.GetPolys().GetData())
    indexes = np.unique(polys_data)
    mesh_points = mesh_points[indexes]

    # get plane with crown centroid as origin
    # and cross product of angulation and symmetry axes as normal
    centroid = get_centroid(mesh)
    plane = vtk.vtkPlane()
    plane.SetOrigin(centroid)
    plane.SetNormal(np.cross(angulation_axis, symmetry_axis))

    # cut mesh with plane
    cutter = vtk.vtkCutter()
    cutter.SetCutFunction(plane)
    cutter.SetInputData(mesh)
    cutter.GenerateValues(1, .0, .0)
    cutter.Update()
    contour_stripper = vtk.vtkStripper()
    contour_stripper.SetInputConnection(cutter.GetOutputPort())
    contour_stripper.Update()

    contour_stripper_out = contour_stripper.GetOutput()
    points = vtk.util.numpy_support.vtk_to_numpy(contour_stripper_out.GetPoints().GetData())

    # rotate so angulation axis aligns with X axis
    angulation_angle = angle(angulation_axis, np.array((1.0, .0, .0)))
    rotation_matrix = get_rotation_matrix(np.cross(angulation_axis, np.array((1.0, .0, .0))), angulation_angle)
    new_points = rotation_matrix.dot(points.T).T

    # split points by mean X coordinate into 2 arrays
    points_left = points[new_points[:, 0] <= new_points[:, 0].mean()]
    points_right = points[new_points[:, 0] > new_points[:, 0].mean()]
    # sort them by Z axis
    if 'upper' == jaw_type:
        points_left = points_left[points_left[:, 1].argsort()[::-1]]
        points_right = points_right[points_right[:, 1].argsort()[::-1]]
    elif 'lower' == jaw_type:
        points_left = points_left[points_left[:, 1].argsort()]
        points_right = points_right[points_right[:, 1].argsort()]

    # find two points with maximum distance between them
    min_ind = min(points_right.shape[0], points_left.shape[0])
    dist = np.sqrt(np.square(points_right[:min_ind] - points_left[:min_ind]).sum())
    max_ind = dist.argmax()

    # get those points
    left_point = points_left[max_ind]
    right_point = points_right[max_ind]

    if tooth_id % 10 < 4:
        # order them by X coordinate
        if left_point[0] > right_point[0]:
            left_point, right_point = right_point, left_point
    else:
        # order them by Y coordiante
        if tooth_id // 10 in (2, 3) and left_point[2] < right_point[2]:
            left_point, right_point = right_point, left_point
        elif tooth_id // 10 in (1, 4) and left_point[2] > right_point[2]:
            left_point, right_point = right_point, left_point
    return left_point.tolist(), right_point.tolist()


def GetSymmetryAxis(id_mesh_dict: Dict[int, vtk.vtkPolyData],
                    features_dict: Dict) -> Dict:
    # Load symmetry points dict if saved file it exists
    symmetry_dict = {}
    contact_points_dict = {}

    for tooth_id in id_mesh_dict.keys():
        # Pass working both molars. We'll NOT be working with them
        if tooth_id % 10 not in (1, 2, 3, 4):
            continue
        log.info(tooth_id)

        symmetry_axis = []
        if True:  # org
            # Here we'll be working only with incisors and canines
            if tooth_id % 10 in (1, 2, 3):
                # Upper arch teeth
                if tooth_id // 10 in (1, 2):
                    symmetry_axis = get_symmetry_axis(id_mesh_dict[tooth_id],
                                                      tooth_id,
                                                      hill_point=features_dict[tooth_id]['hill_points'][0],
                                                      cutting_edge=np.asarray(features_dict[tooth_id]['cutting_edge']))
                # Lower arch teeth
                else:
                    symmetry_axis = get_symmetry_axis(id_mesh_dict[tooth_id], tooth_id)
            # Here we'll be working only with premolars
            elif tooth_id % 10 in (4,):
                symmetry_axis = get_symmetry_axis_circle_projection(id_mesh_dict[tooth_id], tooth_id)

        # Save computed symmetry axis to dict
        symmetry_dict[tooth_id] = {'symmetry_axis': symmetry_axis,
                                   'angulation_axis': [],
                                   'origin': []}
        # Load cutting edges
        cutting_edge = features_dict[tooth_id]['cutting_edge']
        mesh_points = vtk.util.numpy_support.vtk_to_numpy(id_mesh_dict[tooth_id].GetPoints().GetData())
        cutting_edge = mesh_points[cutting_edge]

        # Check whether we're working with the upper or lower arch
        jaw_type = ''
        if tooth_id // 10 in (1, 2):
            jaw_type = 'upper'
        elif tooth_id // 10 in (3, 4):
            jaw_type = 'lower'

        # Launch search for the angulation axis with correct parameters
        origin, angulation_axis = get_angulation_axis(id_mesh_dict[tooth_id],
                                                      cutting_edge,
                                                      symmetry_axis=symmetry_axis,
                                                      jaw_type=jaw_type,
                                                      tooth_id=tooth_id)
        # write to dict
        symmetry_dict[tooth_id]['angulation_axis'] = angulation_axis
        symmetry_dict[tooth_id]['origin'] = origin

        # find rotation matrix from tooth local coordinate system to global coordinate system
        if tooth_id // 10 in (1, 2):
            # deal with upper arch
            symmetry_angle = angle(symmetry_axis, np.array((0.0, 1.0, 0.0)))
            if symmetry_angle > pi / 2:
                symmetry_axis = -np.asarray(symmetry_axis)
            rotation_matrix = rotation(np.asarray(symmetry_axis), np.array((0.0, 1.0, .0)))
        else:
            # deal with lower arch
            symmetry_angle = angle(symmetry_axis, np.array((0.0, -1.0, 0.0)))
            if symmetry_angle > pi / 2:
                symmetry_axis = -np.asarray(symmetry_axis)
            rotation_matrix = rotation(np.asarray(symmetry_axis), np.array((0.0, -1.0, .0)))

        # rotate with matrix computed earlier
        centroid = get_centroid(id_mesh_dict[tooth_id])
        new_points = rotation_matrix.dot((mesh_points - centroid).T).T + centroid
        id_mesh_dict[tooth_id].GetPoints().SetData(vtk.util.numpy_support.numpy_to_vtk(new_points))

        # get angulation axis from dict
        origin, angulation_axis = symmetry_dict[tooth_id]['origin'], symmetry_dict[tooth_id]['angulation_axis']
        origin = np.asarray(origin)
        angulation_axis = np.asarray(angulation_axis)

        # rotate them with matrix
        origin, angulation_axis = [(rotation_matrix.dot((origin - centroid).T).T + centroid)[0],
                                   rotation_matrix.dot(angulation_axis.T).T]
        # launch search for contact points
        points = find_contact_points(id_mesh_dict[tooth_id],
                                     tooth_id,
                                     angulation_axis,
                                     origin,
                                     np.asarray((0.0, 1.0, 0.0)),
                                     jaw_type=jaw_type)

        # rotate contact points and mesh points from local coordinate system to global
        contact_points_dict[tooth_id] = (np.linalg.inv(rotation_matrix).dot(
            (np.asarray(points) - centroid).T).T + centroid).tolist()

        id_mesh_dict[tooth_id].GetPoints().SetData(
            vtk.util.numpy_support.numpy_to_vtk(mesh_points))
        # write contact points to dict
        symmetry_dict[tooth_id]['contact_points'] = contact_points_dict[tooth_id]

    return symmetry_dict
