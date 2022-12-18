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
from utils import (angle, get_centroid, get_line_centroid, get_rotation_matrix, load_features, rotation, vector_l2_norm)

warnings.simplefilter(action='ignore', category=FutureWarning)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('symmetry')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

def dist_to_circle_sum(
        R: float,
        center: np.ndarray,
        points: np.ndarray) -> float:
    """
    Calculate sum of distances from points to circle

    :param R: (3,) circle radius
    :param center: (3,) circle center
    :param points: (N, 3) points
    """
    dists_to_center = np.sqrt(np.square(points - center).sum(axis=-1))
    dists_to_circle = np.abs(dists_to_center - R)
    return dists_to_circle.sum()


def calc_R(c: np.ndarray, x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """
    Calculate the distance of each 2D points from the center (xc, yc)
    
    :param c: (2,) circle center
    :param x: point x coordinate
    :param y: point y coordinate
    """
    xc, yc = c
    return np.sqrt((x - xc)**2 + (y - yc)**2)


def f_2(c: np.ndarray, x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """
    Calculate the algebraic distance between the data points and the mean circle centered at c=(xc, yc)
    
    :param c: (2,) circle center
    :param x: point x coordinate
    :param y: point y coordinate
    """
    Ri = calc_R(c, x, y)
    return Ri - Ri.mean()


def unit_vector(vector: np.ndarray) -> np.ndarray:
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
    return np.arccos(np.clip(np.dot(v1_u, v2_u), -1.0, 1.0))


def get_symmetry_axis_circle_projection(
    mesh: vtk.vtkPolyData,
    tooth_id: int) -> List[int]: #np.ndarray:
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


    print(f" get_symmetry_axis_circle_projection ==================== tooth_id = {tooth_id} =============")
    #print("{0}: get_symmetry_axis_circle_projection() entered".format(datetime.date.today()))
    ANGLE_NUM = 50 # 100 old!!

    initial_vector = np.asarray([1.0, 0.0])
    rotation_values = np.linspace(-45.0, 45.0, 45) # np.linspace(-45.0, 45.0, 90) old
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

    indexes = np.unique(polys_data)
    points = points[indexes]
    points -= centroid

    # Start fitting iterations
    for i in range(ANGLE_NUM):
        angle = 360 / ANGLE_NUM * i
        angle_rad = float(angle) * pi / 180
        rotation_matrix = np.asarray([
            [cos(angle_rad), -sin(angle_rad)],
            [sin(angle_rad), cos(angle_rad)]
        ])
        # Apply first rotation (Y axis)
        rotation_axis = rotation_matrix.dot(initial_vector)
        #print(f"   angle: [{i}, {angle_rad}], Axis:  {rotation_axis}")
        for j in range(rotation_values.shape[0]):
            angles.append(angle)
            rotation_angles.append(rotation_values[j])
            rotation_matrix = get_rotation_matrix(np.asarray((rotation_axis[0], 0, rotation_axis[1])),rotation_values[j] * pi / 180)

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

    rotation_matrix = np.asarray([
        [cos(angle_rad), -sin(angle_rad)],
        [sin(angle_rad), cos(angle_rad)]]
    )

    rotation_axis = rotation_matrix.dot(initial_vector).tolist()
    rotation_matrix = get_rotation_matrix(
        np.asarray((rotation_axis[0], 0, rotation_axis[1])),
        -angle_rad
    )
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


def get_symmetry_axis(
        mesh: vtk.vtkPolyData,
        tooth_id: int,
        hill_point=0,
        cutting_edge=None) -> List[int]: # np.ndarray:
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


def get_angulation_axis(
        mesh: vtk.vtkPolyData,
        cutting_edge: np.ndarray,
        symmetry_axis: List[int], #np.ndarray,
        jaw_type: str,
        tooth_id: int) -> Tuple[List[int], List[int]]: # Tuple[np.ndarray, np.ndarray]:
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

    print(f"get_angulation_axis ==================== tooth_id = {tooth_id} =============")

    # Load, convert mesh data adn compute centroid
    mesh_points = vtk.util.numpy_support.vtk_to_numpy(
        mesh.GetPoints().GetData())
    polys_data = numpy_support.vtk_to_numpy(mesh.GetPolys().GetData())
    polys_data = polys_data.reshape(
        polys_data.shape[0] // 4, 4)[..., 1:].flatten()
    indexes = np.unique(polys_data)
    mesh_points = mesh_points[indexes]
    centroid = get_centroid(mesh)

    # Project cutting edge onto a plane that's defines with the symmetry axis as a normal
    mean_point = np.zeros((3, ))

    symmetry_axis = np.asarray(symmetry_axis)
    projection_points = centroid + (cutting_edge - centroid).dot(symmetry_axis.T).reshape((
        cutting_edge.shape[0], 1)).dot(symmetry_axis.reshape((1, 3)))
    
    mean_point = projection_points.mean(axis=0)
    projection_points = cutting_edge -\
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
        min_point = mesh_projection_points[
            mesh_projection_points[:, 1].argmax()]
    elif 'lower' == jaw_type:
        min_point = mesh_projection_points[
            mesh_projection_points[:, 1].argmin()]
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


def find_contact_points(
        mesh: vtk.vtkPolyData,
        tooth_id: int,
        angulation_axis: np.ndarray,
        origin: np.ndarray,
        symmetry_axis,
        jaw_type: str) -> Tuple[List[int], List[int]]: #np.ndarray:
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
    mesh_points = vtk.util.numpy_support.vtk_to_numpy(
        mesh.GetPoints().GetData())
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
    points = vtk.util.numpy_support.vtk_to_numpy(
        contour_stripper_out.GetPoints().GetData())

    # rotate so angulation axis aligns with X axis
    angulation_angle = angle(angulation_axis, np.array((1.0, .0, .0)))
    rotation_matrix = get_rotation_matrix(
        np.cross(angulation_axis, np.array((1.0, .0, .0))), angulation_angle)
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
    dist = np.sqrt(
        np.square(points_right[:min_ind] - points_left[:min_ind]).sum())
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

def visualize_axis(
        id_mesh_dict: Dict[int, vtk.vtkPolyData],
        id_symmetry_dict,
        jaw_type):
    """Visualize axes and contact points

    :param id_mesh_dict: mesh for each crown
    :param id_symmetry_dict: symmetry as loaded from OBJ file
    :param jaw_type: one of "lower"/"upper"
    """
    renderer = vtk.vtkRenderer()
    for tooth_id in id_mesh_dict.keys():
        if jaw_type == 'lower' and tooth_id // 10 in (1, 2):
            continue
        if jaw_type == 'upper' and tooth_id // 10 in (3, 4):
            continue
        input_mapper = vtk.vtkPolyDataMapper()
        input_mapper.SetInputData(id_mesh_dict[tooth_id]['mesh'])
        input_actor = vtk.vtkActor()
        input_actor.GetProperty().SetColor(0.9, 0.9, 0.9)
        input_actor.SetMapper(input_mapper)
        renderer.AddActor(input_actor)
        if tooth_id % 10 in (1, 2, 3, 4):
            origin = np.asarray(id_symmetry_dict[tooth_id]['origin'])
            angulation_axis = np.asarray(
                id_symmetry_dict[tooth_id]['angulation_axis'])
            symmetry_axis = np.asarray(
                id_symmetry_dict[tooth_id]['symmetry_axis'])
            contact_points = id_symmetry_dict[tooth_id]['contact_points']

            vtk_contact_points = vtk.vtkPoints()
            contact_line = vtk.vtkCellArray()
            contact_pd = vtk.vtkPolyData()
            contact_pd.SetPoints(vtk_contact_points)
            contact_pd.SetLines(contact_line)
            left_point_id = vtk_contact_points.InsertNextPoint(
                contact_points[0])
            right_point_id = vtk_contact_points.InsertNextPoint(
                contact_points[1])
            line = vtk.vtkLine()
            line.GetPointIds().SetId(0, left_point_id)
            line.GetPointIds().SetId(1, right_point_id)
            contact_line.InsertNextCell(line)
            contact_mapper = vtk.vtkPolyDataMapper()
            contact_mapper.SetInputData(contact_pd)
            contact_actor = vtk.vtkActor()
            contact_actor.GetProperty().SetColor(1.0, 0.0, 0.0)
            contact_actor.GetProperty().SetLineWidth(3)
            contact_actor.SetMapper(contact_mapper)

            left_sphere_source = vtk.vtkSphereSource()
            left_sphere_source.SetCenter(*contact_points[0])
            left_sphere_source.SetRadius(0.3)
            left_sphere_source.Update()
            left_contact_mapper = vtk.vtkPolyDataMapper()
            left_contact_mapper.SetInputData(left_sphere_source.GetOutput())
            left_contact_actor = vtk.vtkActor()
            left_contact_actor.GetProperty().SetColor(0.0, 1.0, 0.0)
            left_contact_actor.SetMapper(left_contact_mapper)

            right_sphere_source = vtk.vtkSphereSource()
            right_sphere_source.SetCenter(*contact_points[1])
            right_sphere_source.SetRadius(0.3)
            right_sphere_source.Update()
            right_contact_mapper = vtk.vtkPolyDataMapper()
            right_contact_mapper.SetInputData(right_sphere_source.GetOutput())
            right_contact_actor = vtk.vtkActor()
            right_contact_actor.GetProperty().SetColor(0.0, 0.0, 1.0)
            right_contact_actor.SetMapper(right_contact_mapper)

            origin_sphere_source = vtk.vtkSphereSource()
            origin_sphere_source.SetCenter(origin)
            origin_sphere_source.SetRadius(0.3)
            origin_sphere_source.Update()
            origin_contact_mapper = vtk.vtkPolyDataMapper()
            origin_contact_mapper.SetInputData(origin_sphere_source.GetOutput())
            origin_contact_actor = vtk.vtkActor()
            origin_contact_actor.GetProperty().SetColor(0.0, 1.0, 0.8)
            origin_contact_actor.SetMapper(origin_contact_mapper)

            line_source = vtk.vtkLineSource()
            line_source.SetPoint1(origin)
            line_source.SetPoint2(origin + 5 * angulation_axis)
            line_source.Update()
            line_source_1 = vtk.vtkLineSource()
            line_source_1.SetPoint1(origin)
            line_source_1.SetPoint2(origin + symmetry_axis * 15)
            line_source_1.Update()
            line_mapper = vtk.vtkPolyDataMapper()
            line_mapper.SetInputData(line_source.GetOutput())
            line_actor = vtk.vtkActor()
            line_actor.GetProperty().SetLineWidth(3)
            line_actor.GetProperty().SetColor(1.0, 0.8, 0.0)
            line_actor.SetMapper(line_mapper)
            line_mapper_1 = vtk.vtkPolyDataMapper()
            line_mapper_1.SetInputData(line_source_1.GetOutput())
            line_actor_1 = vtk.vtkActor()
            line_actor_1.GetProperty().SetLineWidth(3)
            line_actor_1.GetProperty().SetColor(1.0, 0.8, 0.0)
            line_actor_1.SetMapper(line_mapper_1)

            renderer.AddActor(line_actor)
            renderer.AddActor(line_actor_1)
            renderer.AddActor(contact_actor)
            renderer.AddActor(left_contact_actor)
            renderer.AddActor(right_contact_actor)
            renderer.AddActor(origin_contact_actor)

    render_window = vtk.vtkRenderWindow()
    render_window.AddRenderer(renderer)
    render_window.SetSize(1024, 1080)  # TODO:
    interactor = vtk.vtkRenderWindowInteractor()
    interactor.SetRenderWindow(render_window)
    renderer.SetBackground(0.1, 0.2, 0.3)
    render_window.Render()
    interactor.Start()


if __name__ == '__main__':
    """Find symmetry axes

    This script looks for symmetry axes and computes tooth contact points
    """  
    from pathlib import Path
    from inspect import currentframe, getframeinfo
    from optparse import OptionParser

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
    parser.add_option("-q", "--quiet",
                    action="store",
                    dest="verbose",
                    default=1,
                    type='int',
                    help="set log 0=get environ LOG_LEVEL, 1=DEBUG, 2, 3, 4, 5=FATAL [default: 1]")
    parser.add_option("-r", "--recalc",
                    action="store_true", dest="recalculate",
                    help="features: to recalculate new...")

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

    # Read session configuration
    directory = Path(getframeinfo(currentframe()).filename).resolve().parents[0]

    session_filename = options.session_filename
    if not session_filename:
        session_filename = directory / 'session.json'
    log.info(f'MY_TEST session filename : {session_filename}')

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


    id_mesh_dict = {}
    if False:
        from teeth_movement.classification import classify_teeth
        from teeth_movement.utils import preprocess_mesh, separate_connected_components
        from teeth_movement.mesh_io import read_stl

        OUT_POLY_COEF = 0.8
        if "out_poly_coef" in config_data:
            out_poly_coef = config_data['out_poly_coef']
            log.info(f'out_poly_coef : {OUT_POLY_COEF}')
        else:
            log.info(f'out_poly_coef not def, set default: {OUT_POLY_COEF}')

        ITER_NUM = 2 # 2 org #4 incr if bad symmetry_axis
        if "iter_num" in config_data:
            out_poly_coef = config_data['iter_num']
            log.info(f'iter_num : {ITER_NUM}')
        else:
            log.info(f'iter_num not def, set default: {ITER_NUM}')

        RELAXATION_FACTOR = 0.1 # 0.01            
        if "relaxation_factor" in config_data:
            out_poly_coef = config_data['relaxation_factor']
            log.info(f'relaxation_factor : {RELAXATION_FACTOR}')
        else:
            log.info(f'relaxation_factor not def, set default: {RELAXATION_FACTOR}')

        OUT_POLY_NUM = 60000
        if "out_poly_num" in config_data:
            out_poly_coef = config_data['out_poly_num']
            log.info(f'out_poly_num : {OUT_POLY_NUM}')
        else:
            log.info(f'out_poly_num not def, set default: {OUT_POLY_NUM}')

        lower_teeth_mesh = read_stl(lower_model_path)
        upper_teeth_mesh = read_stl(upper_model_path)

        lower_teeth_mesh = preprocess_mesh(lower_teeth_mesh, log, 
                                        ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)
        upper_teeth_mesh = preprocess_mesh(upper_teeth_mesh, log, 
                                        ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)

        id_mesh_dict = classify_teeth(
                separate_connected_components(lower_teeth_mesh), 
                separate_connected_components(upper_teeth_mesh),
                missing_id)
    else:
        # Read teeth mesh specified in the config data
        id_mesh_dict = read_obj_teeth(os.path.join(directory_out, f'{case_id}_teeth.obj'))
        
    id_mesh_dict = {key: {'mesh': value}
                    for key, value in id_mesh_dict.items()}

    log.info(f'options.recalculate={options.recalculate}')

    features_file = os.path.join(directory_out, f'features_{case_id}.json')
    if os.path.isfile(features_file):
        log.info(f'Load features_{case_id}.json...')
        features_dict = load_features(
            features_file,
            id_mesh_dict
        )
        if not features_dict:
            log.error(f'Load features_{case_id}.json error.')
            exit(1)

        DEBUG_TEST = False # test - load/write dump files: axis, origin

        LOAD_TEST = False # False - write dump json / True - load dump symmetry axis
        LOAD_TEST_AO = False # False - write dump json / True - load dump  angulation axis + load dump origin

        symmetry_axis_dict = {}     # for DEBUG_TEST
        angulation_axis_dict = {}   # for DEBUG_TEST
        origin_dict = {}            # for DEBUG_TEST
        if DEBUG_TEST:
            if LOAD_TEST:
                symmetry_axis_dict = json.load(
                    open(os.path.join(directory_out, f'symmetry_axis_{case_id}.json'), 'rt'))
            if LOAD_TEST_AO:
                angulation_axis_dict = json.load(
                    open(os.path.join(directory_out, f'angulation_axis_{case_id}.json'), 'rt'))            
                origin_dict = json.load(
                    open(os.path.join(directory_out, f'origin_{case_id}.json'), 'rt'))
        else:
            LOAD_TEST = False 
            LOAD_TEST_AO = False

        # Load symmetry points dict if saved file it exists
        id_symmetry_dict = {}
        if not options.recalculate \
                and os.path.isfile(os.path.join(directory_out, f'symmetry_{case_id}.json')):
            log.info(f'load symmetry_{case_id}.json...')
            id_symmetry_dict = json.load(open(
                os.path.join(directory_out, f'symmetry_{case_id}.json')
            ))
            id_symmetry_dict = {int(key): val for key,
                                val in id_symmetry_dict.items()}
        else:
            log.info('Compute symmetry axes.')
            constact_points_dict = {}

            for tooth_id in id_mesh_dict.keys():
                # Pass working woth molars. We'll NOT be working with them
                if tooth_id % 10 not in (1, 2, 3, 4):
                    continue
                log.info(tooth_id)

                symmetry_axis = []
                if not LOAD_TEST:
                    if True: # org
                        # Here we'll be working only with incisors and canines
                        if tooth_id % 10 in (1, 2, 3):
                            # Upper arch teeth
                            if tooth_id // 10 in (1, 2):
                                symmetry_axis = get_symmetry_axis(
                                    id_mesh_dict[tooth_id]['mesh'],
                                    tooth_id,
                                    hill_point=features_dict[tooth_id]['hill_points'][0],
                                    cutting_edge=np.asarray(features_dict[tooth_id]['cutting_edge'])
                                )
                            # Lower arch teeth
                            else:
                                symmetry_axis = get_symmetry_axis(
                                    id_mesh_dict[tooth_id]['mesh'],
                                    tooth_id
                                )
                        # Here we'll be working only with premolars
                        elif tooth_id % 10 in (4, ):
                            symmetry_axis = get_symmetry_axis_circle_projection(
                                id_mesh_dict[tooth_id]['mesh'],
                                tooth_id
                            )
                    else: # use extract_features_new.py    
                        if tooth_id % 10 in (1, 2, 3):
                            symmetry_axis = get_symmetry_axis(
                                                    id_mesh_dict[tooth_id]['mesh'],
                                                    tooth_id)
                        elif tooth_id % 10 in (4, ):
                            symmetry_axis = get_symmetry_axis_circle_projection(
                                            id_mesh_dict[tooth_id]['mesh'],
                                            tooth_id)

                    if DEBUG_TEST:
                        symmetry_axis_dict[tooth_id] = symmetry_axis
                elif DEBUG_TEST:
                    symmetry_axis = symmetry_axis_dict[str(tooth_id)]

                # Save computed symmetry axis to dict
                id_symmetry_dict[tooth_id] = {
                    'symmetry_axis': symmetry_axis,
                    'angulation_axis': [],
                    'origin': []
                }

                # Load cutting edges
                cutting_edge = features_dict[tooth_id]['cutting_edge']
                mesh_points = vtk.util.numpy_support.vtk_to_numpy(
                    id_mesh_dict[tooth_id]['mesh'].GetPoints().GetData()
                )
                cutting_edge = mesh_points[cutting_edge]

                # Check whether we're working with the upper or lower arch
                jaw_type = ''
                if tooth_id // 10 in (1, 2):
                    jaw_type = 'upper'
                elif tooth_id // 10 in (3, 4):
                    jaw_type = 'lower'

                origin, angulation_axis = None, None
                if not LOAD_TEST_AO: # tmp
                    # Launch search for the angulation axis with correct parameters
                    origin, angulation_axis = get_angulation_axis(
                        id_mesh_dict[tooth_id]['mesh'],
                        cutting_edge,
                        symmetry_axis=symmetry_axis,
                        jaw_type=jaw_type,
                        tooth_id=tooth_id
                    )
                    
                    if DEBUG_TEST:
                        angulation_axis_dict[tooth_id] = angulation_axis
                        origin_dict[tooth_id] = origin
                elif DEBUG_TEST:
                    origin = origin_dict[str(tooth_id)]
                    angulation_axis = angulation_axis_dict[str(tooth_id)]

                # write to dict
                id_symmetry_dict[tooth_id]['angulation_axis'] = angulation_axis
                id_symmetry_dict[tooth_id]['origin'] = origin

                # find rotation matrix from tooth local coordiante system to global coordinate system
                rotation_matrix = None
                if tooth_id // 10 in (1, 2):
                    # deal with upper arch
                    symmetry_angle = angle(symmetry_axis, np.array((0.0, 1.0, 0.0)))
                    if symmetry_angle > pi / 2:
                        symmetry_axis = -np.asarray(symmetry_axis)
                    rotation_matrix = rotation(
                        np.asarray(symmetry_axis),
                        np.array((0.0, 1.0, .0))
                    )
                else:
                    # deal with lower arch
                    symmetry_angle = angle(symmetry_axis, np.array((0.0, -1.0, 0.0)))
                    if symmetry_angle > pi / 2:
                        symmetry_axis = -np.asarray(symmetry_axis)
                    rotation_matrix = rotation(
                        np.asarray(symmetry_axis),
                        np.array((0.0, -1.0, .0))
                    )
                # rotate with matrix computed earlier
                centroid = get_centroid(id_mesh_dict[tooth_id]['mesh'])
                
                new_points = rotation_matrix.dot(
                    (mesh_points - centroid).T).T + centroid
                
                id_mesh_dict[tooth_id]['mesh'].GetPoints().SetData(
                    vtk.util.numpy_support.numpy_to_vtk(new_points))

                # get angluation axis from dict                
                origin, angulation_axis =\
                    id_symmetry_dict[tooth_id]['origin'], id_symmetry_dict[tooth_id]['angulation_axis']

                origin = np.asarray(origin)
                angulation_axis = np.asarray(angulation_axis)

                # rotate them with matrix
                origin, angulation_axis = [
                    (rotation_matrix.dot(
                        (origin - centroid).T).T + centroid)[0],
                    rotation_matrix.dot(angulation_axis.T).T
                ]
                # launch search for contach points
                points = find_contact_points(
                    id_mesh_dict[tooth_id]['mesh'],
                    tooth_id,
                    angulation_axis,
                    origin,
                    np.asarray((0.0, 1.0, 0.0)),
                    jaw_type=jaw_type
                )

                # rotate contact points and mesh points from local coodinate system to global
                constact_points_dict[tooth_id] = (np.linalg.inv(rotation_matrix).dot(
                    (np.asarray(points) - centroid).T).T + centroid).tolist()

                id_mesh_dict[tooth_id]['mesh'].GetPoints().SetData(
                    vtk.util.numpy_support.numpy_to_vtk(mesh_points))
                # write contact points to dict
                id_symmetry_dict[tooth_id]['contact_points'] = constact_points_dict[tooth_id]
            # save axes and contact points to JSON files
            json.dump(
                id_symmetry_dict,
                open(os.path.join(directory_out, f'symmetry_{case_id}.json'), 'wt')
            )
            json.dump(
                constact_points_dict,
                open(os.path.join(directory_out, f'contact_points_{case_id}.json'), 'wt')
            )

            if DEBUG_TEST:
                if not LOAD_TEST: # tmp
                    #tmp
                    json.dump(
                        symmetry_axis_dict,
                        open(os.path.join(directory_out, f'symmetry_axis_{case_id}.json'), 'wt')
                    )
                if not LOAD_TEST_AO: # tmp
                    json.dump(
                        angulation_axis_dict,
                        open(os.path.join(directory_out, f'angulation_axis_{case_id}.json'), 'wt')
                    )                
                    json.dump(
                        origin_dict,
                        open(os.path.join(directory_out, f'origin_{case_id}.json'), 'wt')
                    )

        # launch visualization
        if options.jaw_type:
            visualize_axis(
                id_mesh_dict,
                id_symmetry_dict,
                jaw_type=options.jaw_type
            )
    else:
        log.error('Features file not found')
