import json
import math
import pickle
from typing import Dict, List
import numpy as np
import vtk
from vtk.util import numpy_support


def calc_R(c: np.ndarray,
           x: np.ndarray,
           y: np.ndarray) -> np.ndarray:
    """
    Calculate the distance of each 2D points from the center (xc, yc)

    :param c: (2,) circle center
    :param x: point x coordinate
    :param y: point y coordinate
    """
    xc, yc = c
    return np.sqrt((x - xc)**2 + (y - yc)**2)


def f_2(c: np.ndarray,
        x: np.ndarray,
        y: np.ndarray) -> np.ndarray:
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


def dist_to_circle_sum(R: float,
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


def rotation(A: np.ndarray,
             B: np.ndarray) -> np.ndarray:
    """Rotation from vec A to vec B

    Calculates rotation between 2 vectors

    :param A: vector with the size 3
    :type A: np.ndarray
    :param B: vector with the size 3
    :type B: np.ndarray
    :returns: 3x3 rotation matrix
    :rtype: {np.ndarray}
    """
    def ssc(v):
        return np.asarray([
            [0, -v[2], v[1]],
            [v[2], 0, -v[0]],
            [-v[1], v[0], 0]])
    tmp = ssc(np.cross(A, B))
    RU = np.eye(3) + tmp + \
        tmp @ tmp / (1 + np.dot(A, B))
    return RU


def get_rotation_matrix(axis, theta):
    """ calculate rotation matrix along give axis to angle theta """
    axis = np.asarray(axis)
    axis = axis / math.sqrt(np.dot(axis, axis))
    a = math.cos(theta / 2.0)
    b, c, d = -axis * math.sin(theta / 2.0)
    aa, bb, cc, dd = a * a, b * b, c * c, d * d
    bc, ad, ac, ab, bd, cd = b * c, a * d, a * c, a * b, b * d, c * d
    return np.array([[aa + bb - cc - dd, 2 * (bc + ad), 2 * (bd - ac)],
                     [2 * (bc - ad), aa + cc - bb - dd, 2 * (cd + ab)],
                     [2 * (bd + ac), 2 * (cd - ab), aa + dd - bb - cc]])


def vector_l2_norm(vec: np.ndarray) -> float:
    """Vector normalisation

    Normalises provided vector to float

    :param vec: vector with the size 3
    :type vec: np.ndarray
    :returns: Normalised vector as float
    :rtype: {float}
    """
    return math.sqrt(np.square(vec).sum())


def angle(v1, v2):
    """Get angle between two vectors (in radians)

    :param v1: (N,) vector
    :param v2: (N,) vector
    :return: float angle in radians
    """
    return math.acos(np.dot(v1, v2) / (vector_l2_norm(v1) * vector_l2_norm(v2)))


def dist(point_1: np.ndarray,
         point_2: np.ndarray) -> float:
    """Distance between points

    Computes distance between 2 points

    :param point_1: Point 1 coordinate
    :type point_1: np.ndarray
    :param point_2: Point 2 coordinate
    :type point_2: np.ndarray
    :returns: Distance as float
    :rtype: {float}
    """
    return vector_l2_norm(point_2 - point_1)


def lines_similarity_measure(line_1: np.ndarray,
                             line_2: np.ndarray) -> float:
    """Lines similarity metric

    Measures lines similarity by computing
    For each point of line 1 (N)
    looks for the closest point in line 2 (M)
    and computes an (N,M) distance matrix

    :param line_1: (N,3) array
    :type line_1: np.ndarray
    :param line_2: (M,3) array
    :type line_2: np.ndarray
    :returns: Distance matrix between 2 lines
    :rtype: {float}
    """
    arrays = [line_1 for _ in range(line_2.shape[0])]
    line_1_stack = np.stack(arrays, axis=1)
    # Computing (N,M) distance matrix
    dist_matrix = (np.square(line_1_stack - line_2).sum(axis=-1))
    return dist_matrix.min(axis=-1).sum() / (line_1.shape[0] + line_2.shape[0])


def line_most_remote_points(line: np.ndarray) -> np.ndarray:
    """Compute furthest points

    Calcualtes 2 points of the line
    that are the furthest away from each other

    :param line: Line as array of points
    :type line: np.ndarray
    :returns: Array with size 2 containing fount points
    :rtype: {np.ndarray}
    """
    arrays = [line for _ in range(line.shape[0])]
    line_stack = np.stack(arrays, axis=1)
    dist_matrix = (np.square(line_stack - line).sum(axis=-1))
    result = np.zeros((2, 3))
    tmp_argmax = dist_matrix.argmax()
    result[0] = line[tmp_argmax // line.shape[0]]
    result[1] = line[tmp_argmax % line.shape[0]]
    return result


def chunks_generator(l, n):
    """Chunk generator

    Generated n chunks from l

    :param l: Number of chunks
    :type l: np.ndarray
    :param n: number of chunks
    :type n: int
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def save_features_np(path: str,
                     id_mesh_dict: Dict,
                     features_dict: Dict):
    """Save tooth features as np file

    Saves tooth features as numpy file with the following structure:
    {
        'hill_points': [],
        'cutting_edge': [],
        'fissures': []
    }

    :param path: Path where to save
    :type path: str
    :param id_mesh_dict: Tooth object dictionary
    :type id_mesh_dict: Dict
    :param features_dict: Extracted features as np array
    :type features_dict: Dict
    """
    new_features_dict = {}
    for key in id_mesh_dict:
        if not is_int(key):
            continue        
        hill_points = features_dict[key]['hill_points']
        points = id_mesh_dict[key]['mesh']
        new_features_dict[key] = {
                'hill_points': [],
                'cutting_edge': [],
                'fissures': []
        }
        for point in hill_points:
            new_features_dict[key]['hill_points'].append(points[point].tolist())
        fissures = features_dict[key]['fissures']
        new_fissures = []
        for fissure in fissures:
            new_fissure = []
            for point in fissure:
                new_fissure.append(points[point].tolist())
            new_fissures.append(new_fissure)
        new_features_dict[key]['fissures'] = new_fissures
        cutting_edge = features_dict[key]['cutting_edge']
        for point in cutting_edge:
            new_features_dict[key]['cutting_edge'].append(points[point].tolist())
    with open(path, 'wb') as outfile:
        pickle.dump(new_features_dict, outfile)


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

        # TODO: Refactor condition
        if key not in features_dict.keys():
            continue

        hill_points = features_dict[key]['hill_points']
        points = numpy_support.vtk_to_numpy(id_mesh_dict[key].GetPoints().GetData())
        new_features_dict[key] = {
                'hill_points': [],
                'cutting_edge': [],
                'fissures': []
        }
        for point in hill_points:
            new_features_dict[key]['hill_points'].append(id_mesh_dict[key].GetPoint(point))
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
            new_features_dict[key]['cutting_edge'].append(id_mesh_dict[key].GetPoint(point))
    with open(path, 'wt') as outfile:
        json.dump(new_features_dict, outfile)


def load_features(path: str,
                  id_mesh_dict: Dict) -> Dict:
    """Loads features from json file

    Loads tooth features from a provided json file that has the following structure:
    {
        'hill_points': [],
        'cutting_edge': [],
        'fissures': []
    }

    :param path: JSON path
    :type path: str
    :param id_mesh_dict: Dictionary woth Tooth IDs
    :type id_mesh_dict: Dict
    :returns: Dictionary with loaded tooth features
    :rtype: {Dict}
    """
    with open(path, 'rt') as infile:
        features_dict = json.load(infile)
        features_dict = {int(key): value for key, value in features_dict.items()}
    new_features_dict = {}
    for key in features_dict.keys():
        if key not in id_mesh_dict:
            continue
        points = numpy_support.vtk_to_numpy(id_mesh_dict[key].GetPoints().GetData())
        new_features_dict[key] = {'hill_points': [], 'fissures': [], 'cutting_edge': []}
        for point in features_dict[key]['hill_points']:
            dists = np.square(points - np.asarray(point)).sum(axis=-1)
            new_features_dict[key]['hill_points'].append(dists.argmin())
        for point in features_dict[key]['cutting_edge']:
            dists = np.square(points - np.asarray(point)).sum(axis=-1)
            new_features_dict[key]['cutting_edge'].append(dists.argmin())
        new_fissures = []
        for fissure in features_dict[key]['fissures']:
            new_fissure = []
            for point in fissure:
                dists = np.square(points - np.asarray(point)).sum(axis=-1)
                new_fissure.append(dists.argmin())
            new_fissures.append(new_fissure)
        new_features_dict[key]['fissures'] = new_fissures
    return new_features_dict


"""
    Decimate and smooth mesh
"""
def smooth_mesh(mesh: vtk.vtkPolyData,
                iter_num: int,
                relaxation_factor: float) -> vtk.vtkPolyData:
    """Smooth mesh

    Smooth mesh using VTK tools

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :param iter_num: Number of smoothing iterations
    :type iter_num: int
    :param relaxation_factor: Relaxation factor as float
    :type relaxation_factor: float
    :returns: Smoothed mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """
    smooth_filter = vtk.vtkSmoothPolyDataFilter()
    smooth_filter.SetInputData(mesh)
    smooth_filter.SetNumberOfIterations(iter_num)
    smooth_filter.SetRelaxationFactor(relaxation_factor)
    smooth_filter.FeatureEdgeSmoothingOff()
    smooth_filter.BoundarySmoothingOn()
    smooth_filter.Update()
    return smooth_filter.GetOutput()


"""
    Decimate and smooth mesh
"""
def preprocess_mesh(mesh: vtk.vtkPolyData,
                    logging=None,
                    iter_num=1,
                    relaxation_factor=0.01,
                    decimation=True,
                    out_poly_num_coefficient=0.8,
                    poly_num=None) -> vtk.vtkPolyData:
    if iter_num and iter_num > 0:
        if logging:
            logging.info(f'smooth iter_num={iter_num}, relaxation_factor={relaxation_factor}')
        smooth_filter = vtk.vtkSmoothPolyDataFilter()
        smooth_filter.SetInputData(mesh)
        smooth_filter.SetNumberOfIterations(iter_num)
        smooth_filter.SetRelaxationFactor(relaxation_factor)
        smooth_filter.Update()
        mesh = smooth_filter.GetOutput()

    if decimation:
        num_of_polys = mesh.GetNumberOfPolys()
        if not poly_num or poly_num <= 0:
            out_poly_num = int(mesh.GetNumberOfCells() * out_poly_num_coefficient)
            if logging:
                logging.info(f'decimate {num_of_polys} to {out_poly_num} opt: coef={out_poly_num_coefficient}')
        else:
            out_poly_num = poly_num
            if logging:
                logging.info(f'decimate {num_of_polys} to {out_poly_num}')

        if 0 < out_poly_num < num_of_polys:
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
    return mesh
 
 
def separate_connected_components(mesh: vtk.vtkPolyData) -> list:
    """Separate connected componenets

    Splits connected components in mesh using VTK

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :returns: List of connected componenets as VTK objects
    :rtype: {list}
    """
    cc_list = []
    connectivity_filter = vtk.vtkPolyDataConnectivityFilter()
    connectivity_filter.SetInputData(mesh)
    connectivity_filter.Update()
    cc_num = connectivity_filter.GetNumberOfExtractedRegions()
    for cc_ind in range(cc_num):
        connectivity_filter = vtk.vtkPolyDataConnectivityFilter()
        connectivity_filter.SetInputData(mesh)
        connectivity_filter.SetExtractionModeToSpecifiedRegions()
        connectivity_filter.AddSpecifiedRegion(cc_ind)
        connectivity_filter.Update()
        clean_poly_data = vtk.vtkCleanPolyData()
        clean_poly_data.SetInputData(connectivity_filter.GetOutput())
        clean_poly_data.Update()
        cc_list.append(clean_poly_data.GetOutput())
    return cc_list


def get_centroid(mesh: vtk.vtkPolyData) -> np.ndarray:
    """Get centroid

    Compute centroid for provided mesh

    :param mesh: Mesh as VTK object
    :type mesh: vtk.vtkPolyData
    :returns: Centroid coordinates as array with size 3
    :rtype: {np.ndarray}
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
    crosses = np.cross(diff_1, diff_2)
    areas = 0.5 * np.sqrt(np.square(crosses).sum(axis=-1))
    centroid = np.sum(centers * np.dstack((areas, areas, areas))[0], axis=0) / areas.sum()
    return centroid


def get_centroid_np(points: np.ndarray, polys: np.ndarray):
    """Get centroid from points&polygons

    Compute centroid from provided points and polygons

    :param points: Array of points
    :type points: np.ndarray
    :param polys: Array of polygons
    :type polys: np.ndarray
    :returns: Centroid coordinates as array with size 3
    :rtype: {np.ndarray}
    """
    polys = points[polys.flatten()]
    polys = polys.reshape(polys.shape[0] // 3, 3, 3)
    centers = polys.sum(axis=-2) / 3
    diff_1 = polys[:, 1, :] - polys[:, 0, :]
    diff_2 = polys[:, 2, :] - polys[:, 0, :]
    crosses = np.cross(diff_1, diff_2)
    areas = 0.5 * np.sqrt(np.square(crosses).sum(axis=-1))
    centroid = np.sum(centers * np.dstack((areas, areas, areas))[0], axis=0) / areas.sum()
    return centroid


def get_line_centroid(line: np.ndarray):
    """Get centroid of a line

    Compute centroid from a provided line

    :param line: Line as nd.array
    :type line: np.ndarray
    :returns: Centroid coordinates as array with size 3
    :rtype: {np.ndarray}
    """
    centers = (line[:line.shape[0] - 1] + line[1:]) / 2
    diff = line[1:] - line[:line.shape[0] - 1]
    lengths = np.sqrt(np.square(diff).sum(axis=-1))
    centroid = np.sum(centers * np.dstack((lengths, lengths, lengths))[0], axis=0) / lengths.sum()
    return centroid


def list_diff(list1:list(), list2:list()):
    """Find difference of two lists"""
    return [item for item in list1 if item not in list2]


def list_intersection(list1:list(), list2:list()):
    """Intersect two lists"""
    return [item for item in list1 if item in list2]


def transform_vtk_mesh(mesh: vtk.vtkPolyData,
                       T: np.ndarray) -> vtk.vtkPolyData:
    """Transform a VTK mesh

    Applies a transformation to a mesh

    :param mesh: Provided mesh
    :type mesh: vtk.vtkPolyData
    :param T: Transformation matrix
    :type T: np.ndarray
    :returns: Transformed mesh
    :rtype: {vtk.vtkPolyData}
    """
    transform = vtk.vtkTransform()
    vtk_matrix = vtk.vtkMatrix4x4()
    for i in range(4):
        for j in range(4):
            vtk_matrix.SetElement(i, j, T[i, j])
    transform.SetMatrix(vtk_matrix)
    transform_filter = vtk.vtkTransformPolyDataFilter()
    transform_filter.SetTransform(transform)
    transform_filter.SetInputData(mesh)
    transform_filter.Update()
    return transform_filter.GetOutput()


def concat_meshes(meshes: List[List[np.ndarray]]) -> vtk.vtkPolyData:
    """Combine meshed

    Combined a set of meshes into one

    :param meshes: List of meshes as np.ndarray
    :type meshes: List[List[np.ndarray]]
    :returns: Combined mesh as VTK object
    :rtype: {[type]}
    """
    new_mesh = vtk.vtkPolyData()
    new_points = None
    new_polys_data = None
    for i, mesh in enumerate(meshes):
        local_points, local_polys_data = mesh
        if new_polys_data is None:
            new_polys_data = local_polys_data
            new_points = local_points
        else:
            new_polys_data = np.concatenate(
                [new_polys_data, local_polys_data + new_points.shape[0]],
                axis=0
            )
            new_points = np.concatenate(
                [new_points, local_points],
                axis=0
            )
    new_points_vtk = vtk.vtkPoints()
    new_points_vtk.SetData(numpy_support.numpy_to_vtk(new_points))
    new_mesh.SetPoints(new_points_vtk)
    new_cells = vtk.vtkCellArray()
    for i in range(new_polys_data.shape[0]):
        new_cells.InsertNextCell(3, new_polys_data[i].tolist())
    new_mesh.SetPoints(new_points_vtk)
    new_mesh.SetPolys(new_cells)
    return new_mesh
