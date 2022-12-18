import vtk
import numpy
from vtk.util import numpy_support
from typing import Dict, List

OUT_POLY_COEF = 0.8
ITER_NUM = 2
RELAXATION_FACTOR = 0.1
OUT_POLY_NUM = 60000


def read_stl(mesh_path: str) -> vtk.vtkPolyData:
    """Read STL

    Reads STL mesh from disk

    :param mesh_path: Path to stl mesh
    :type mesh_path: str
    :returns: Mesh as VTK object
    :rtype: {vtk.vtkPolyData}
    """
    reader = vtk.vtkSTLReader()
    reader.SetFileName(mesh_path)
    reader.Update()
    return reader.GetOutput()


def read_obj(mesh_path: str) -> vtk.vtkPolyData:
    reader = vtk.vtkOBJReader()
    reader.SetFileName(mesh_path)
    reader.Update()
    return reader.GetOutput()


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
    print(f"GetNumberOfExtractedRegions = {cc_num}")
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


def preprocess_mesh(mesh: vtk.vtkPolyData,
                    iter_num=1,
                    relaxation_factor=0.01,
                    decimation=True,
                    out_poly_num_coefficient=0.8,
                    poly_num=None) -> vtk.vtkPolyData:
    if iter_num and iter_num > 0:
        smooth_filter = vtk.vtkSmoothPolyDataFilter()
        smooth_filter.SetInputData(mesh)
        smooth_filter.SetNumberOfIterations(iter_num)
        smooth_filter.SetRelaxationFactor(relaxation_factor)
        smooth_filter.Update()
        mesh = smooth_filter.GetOutput()

    if decimation:
        num_of_polys = mesh.GetNumberOfPolys()
        out_poly_num = 0
        if not poly_num or poly_num <= 0:
            out_poly_num = int(mesh.GetNumberOfCells() * out_poly_num_coefficient)
        else:
            out_poly_num = poly_num

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
    return mesh


def list_diff(list1: list(), list2: list()):
    """Find difference of two lists"""
    return [item for item in list1 if item not in list2]


def get_centroid(mesh: vtk.vtkPolyData) -> numpy.ndarray:
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


def classify_teeth(lower_teeth_meshes: List[vtk.vtkPolyData],
                   upper_teeth_meshes: List[vtk.vtkPolyData],
                   missing_teeth_id: List[int]) -> Dict[int, vtk.vtkPolyData]:
    id_cenrtoid_dict = {}

    # teeth ID in FDI notation
    lower_id = tuple(range(48, 40, -1)) + tuple(range(38, 30, -1))
    upper_id = tuple(range(18, 10, -1)) + tuple(range(28, 20, -1))

    # teeth to classify based on X coordinate
    x_group_lower_id = (43, 42, 41, 31, 32, 33)
    x_group_upper_id = (13, 12, 11, 21, 22, 23)

    # teeth to classify based on Y coordinate
    left_group_lower_id = (48, 47, 46, 45, 44)
    left_group_upper_id = (18, 17, 16, 15, 14)

    print("missing : " + str(missing_teeth_id))
    print("lower_id: " + str(lower_id))
    print("upper_id: " + str(upper_id))
    print("diff = " + str(list_diff(lower_id + upper_id, missing_teeth_id)))
    print("diff len = " + str(len(list_diff(lower_id + upper_id, missing_teeth_id))))
    print("upper_teeth_meshes = " + str(len(upper_teeth_meshes)))
    print("lower_teeth_meshes = " + str(len(lower_teeth_meshes)))

    # if number of connected components != number of teeth raise ValueError
    if len(list_diff(lower_id + upper_id, missing_teeth_id)) != \
            len(lower_teeth_meshes) + len(upper_teeth_meshes):
        raise ValueError(
            f'Wrong missing teeth specification, lower {len(lower_teeth_meshes)}, upper {len(upper_teeth_meshes)}')

    # compute crown centroids
    centroids_lower = numpy.zeros((len(lower_teeth_meshes), 4))
    centroids_upper = numpy.zeros((len(upper_teeth_meshes), 4))
    for i, tooth_model in enumerate(lower_teeth_meshes):
        centroids_lower[i, :3] = get_centroid(tooth_model)
        centroids_lower[i, 3] = i
        # [x, y, z, i]
    for i, tooth_model in enumerate(upper_teeth_meshes):
        centroids_upper[i, :3] = get_centroid(tooth_model)
        centroids_upper[i, 3] = i

    for centroids, id_list, x_group_id, left_group_id in zip(
            [centroids_lower, centroids_upper],
            [lower_id, upper_id],
            [x_group_lower_id, x_group_upper_id],
            [left_group_lower_id, left_group_upper_id]):

        # find id of teeth to classify based on Y coordinate
        y_group_id = list_diff(id_list, x_group_id)
        right_group_id = list_diff(y_group_id, left_group_id)
        y_group_missing_id = list(set(missing_teeth_id).intersection(y_group_id))
        y_group_id = list_diff(y_group_id, y_group_missing_id)

        # find mean X coordinate
        x_mean = centroids[:, 0].mean()
        centroids_left = centroids[centroids[:, 0] < x_mean]
        centroids_right = centroids[centroids[:, 0] >= x_mean]

        # sort by Y coodinate
        centroids_sorted_left = centroids_left[centroids_left[:, 2].argsort()]
        centroids_sorted_right = centroids_right[centroids_right[:, 2].argsort()]
        centroids_y_sorted_left = centroids_sorted_left[:5 - len(set(y_group_missing_id).intersection(left_group_id))]
        centroids_y_sorted_right = centroids_sorted_right[
                                   :5 - len(set(y_group_missing_id).intersection(right_group_id))]

        # classify based on Y coordinate
        centroids_y = numpy.concatenate([centroids_y_sorted_left, centroids_y_sorted_right], axis=0)
        for i, y_id in enumerate(y_group_id):
            id_cenrtoid_dict[y_id] = centroids_y[i]

        # sort by X coordinate
        centroids_x_left = centroids_sorted_left[5 - len(set(y_group_missing_id).intersection(left_group_id)):]
        centroids_x_right = centroids_sorted_right[5 - len(set(y_group_missing_id).intersection(right_group_id)):]
        centroids_x = numpy.concatenate([centroids_x_left, centroids_x_right], axis=0)

        # classify based on X coordinates
        centroids_x = centroids_x[centroids_x[:, 0].argsort()]
        x_group_id = list_diff(x_group_id, missing_teeth_id)
        for i, x_id in enumerate(x_group_id):
            id_cenrtoid_dict[x_id] = centroids_x[i]

    # create resulting dict
    id_model_dict = {}
    for tooth_id in id_cenrtoid_dict:
        if tooth_id in lower_id:
            id_model_dict[tooth_id] = lower_teeth_meshes[int(id_cenrtoid_dict[tooth_id][3])]
        elif tooth_id in upper_id:
            id_model_dict[tooth_id] = upper_teeth_meshes[int(id_cenrtoid_dict[tooth_id][3])]
    return id_model_dict


################################################################################################

def PreprocessMesh():
    lower_model_path = "/home/andtokm/Projects/data/cases/2878/automodeling/crowns/2878_lower.stl";
    upper_model_path = "/home/andtokm/Projects/data/cases/2878/automodeling/crowns/2878_upper.stl";
    missing_id = [17, 18, 27, 28, 37, 38, 47, 48];

    lowerTeethMesh = read_stl(lower_model_path)
    upperTeethMesh = read_stl(upper_model_path)

    lowerTeethMesh = preprocess_mesh(lowerTeethMesh, ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)
    upperTeethMesh = preprocess_mesh(upperTeethMesh, ITER_NUM, RELAXATION_FACTOR, True, OUT_POLY_COEF, OUT_POLY_NUM)

    lowerSeparatedTeeths = separate_connected_components(lowerTeethMesh)
    upperSeparatedTeeths = separate_connected_components(upperTeethMesh)

    print(f"Separated: Lower: {len(lowerSeparatedTeeths)}, Upper: {len(upperSeparatedTeeths)}")

    teeth_map = classify_teeth(lowerSeparatedTeeths, upperSeparatedTeeths, missing_id)

    print(f"Classified map: {len(teeth_map)}")


def CentroidTest():
    lower_tooth1 = read_stl("C:\Projects\cpp\VTK_Tests\DATA_AND_EXAMPLES\data\out\lower_0.stl")
    x = get_centroid(lower_tooth1)
    print(x)


def ClassifyTest():
    file = "C:\Projects\cpp\VTK_Tests\DATA_AND_EXAMPLES\data\models\d0aa_scan_crown.obj"
    polyData = read_obj(file);

    result = separate_connected_components(polyData)
    lowerSeparatedTeeths: List[vtk.vtkPolyData] = result[:14]
    upperSeparatedTeeths: List[vtk.vtkPolyData] = result[14:]

    centroids_lower = numpy.zeros((len(lowerSeparatedTeeths), 4))
    # centroids_upper = numpy.zeros((len(upperSeparatedTeeths), 4))

    # teeth ID in FDI notation
    lower_id = tuple(range(48, 40, -1)) + tuple(range(38, 30, -1))
    # upper_id = tuple(range(18, 10, -1)) + tuple(range(28, 20, -1))

    # teeth to classify based on X coordinate
    x_group_lower_id = (43, 42, 41, 31, 32, 33)
    # x_group_upper_id = (13, 12, 11, 21, 22, 23)

    # teeth to classify based on Y coordinate
    left_group_lower_id = (48, 47, 46, 45, 44)
    # left_group_upper_id = (18, 17, 16, 15, 14)

    for i, tooth_model in enumerate(lowerSeparatedTeeths):
        centroids_lower[i, :3] = get_centroid(tooth_model)
        centroids_lower[i, 3] = i

    '''
    print(lower_id)
    print(x_group_lower_id)
    print(left_group_lower_id)
    '''

    for centroids, id_list, x_group_id, left_group_id in zip(
            [centroids_lower], [lower_id], [x_group_lower_id],[left_group_lower_id]):
        # y_group_id = list_diff(id_list, x_group_id)
        # right_group_id = list_diff(y_group_id, left_group_id)
        # print(y_group_id)
        print(centroids)
        print(id_list)
        print(x_group_id)
        print(left_group_id)


if __name__ == '__main__':
    print("Classify teeths...")
    # CentroidTest()
    ClassifyTest();

    # l = [1,2,3,4]
    # print(l[:2])
    # print(l[2:])