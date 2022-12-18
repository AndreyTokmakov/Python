import json
import logging
import os
import numpy as np
import vtk

from typing import List
from zipfile import error
from shapely.geometry import Polygon
from sklearn.cluster import KMeans
from utils import get_centroid

log = logging.getLogger('isoclines')

class IsoclinesFilter:

    """
    Compute isoclines of crown mesh.

    1. Cut specified 3D triangular mesh with plane
    2. Compute resulting isoclines
    3. Find series of nested isoclines
    """

    def __init__(
            self,
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
        centroid = get_centroid(self.model)

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

        # print(bounds)

        # cut model with planes
        cutter = vtk.vtkCutter()
        cutter.SetCutFunction(plane)
        cutter.SetInputData(self.model)
        cutter.GenerateValues(
                self.isoclines_num + 2, -min_z_dist,
                max_z_dist)
        cutter.Update()

        # print(cutter)

        # stripe contours
        self.contour_stripper = vtk.vtkStripper()
        self.contour_stripper.SetInputConnection(cutter.GetOutputPort())
        self.contour_stripper.Update()

        # convert vtk array to numpy arrays
        contour_stripper_out = self.contour_stripper.GetOutput()
        lines_num = contour_stripper_out.GetNumberOfLines()
        lines_np = vtk.util.numpy_support.vtk_to_numpy(contour_stripper_out.GetLines().GetData())
        points =   vtk.util.numpy_support.vtk_to_numpy(contour_stripper_out.GetPoints().GetData())

        print(f"lines_num = {lines_num}")
        #print(f"lines_num = {lines_num}")
        #print(f"lines_num = {lines_num}")

        # combine contours and remove non-closed ones
        line_ind = 0
        self.lines = []
        self.index_lines = []
        for i in range(lines_num):
            # print(f"i = {i}")
            line = lines_np[line_ind + 1: line_ind + lines_np[line_ind] + 1]
            # print(f"line = {line}")
            line_ind += lines_np[line_ind] + 1
            #print(f"line_ind = {line_ind}")
            if line.size:
                # print(f"appending line {line}")
                self.index_lines.append(line)



        # print(f"self.index_lines = {len(self.index_lines)}")

        self.__combine_contours()
        self.__remove_non_closed_contours()
        self.z_max = points[0, 1]
        self.z_min = points[0, 1]

        # print(f"self.lines = {self.lines}")
        # print(f"self.index_lines = {len(self.index_lines)}")

        for index_line in self.index_lines:
            line = points[index_line]
            self.lines.append(line)
            if line[0, 1] > self.z_max:
                self.z_max = line[0, 1]
            if line[0, 1] < self.z_min:
                self.z_min = line[0, 1]

    def __remove_non_closed_contours(self) -> None:
        # if first point != last point, remove contour
        new_lines = []
        for line in self.index_lines:
            if line[0] == line[-1]:
                new_lines.append(line)
        self.index_lines = new_lines

    def __combine_contours(self) -> None:
        """
        Combine connected contours
        """

        first_points = [line[0] for line in self.index_lines]
        last_points = [line[-1] for line in self.index_lines]
        line_ind = 0

        # print(f"first_points: {first_points}")
        # print(f"last_points: {last_points}")
        # print(f"self.index_lines: {self.index_lines}")

        while line_ind < len(self.index_lines):
            line = self.index_lines.pop(line_ind)
            first_point = first_points.pop(line_ind)
            last_point = last_points.pop(line_ind)

            # first point match first point of other contour -> connect
            if first_point in first_points:
                ind_to_stripe = first_points.index(first_point)
                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)
                new_line = np.concatenate([line_to_stripe[::-1][1:], line])
                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])
            # first point match last point of other contour -> connect
            elif first_point in last_points:
                ind_to_stripe = last_points.index(first_point)
                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)
                new_line = np.concatenate([line_to_stripe, line[1:]])
                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])
            # last point match first point of other contour -> connect
            elif last_point in first_points:
                ind_to_stripe = first_points.index(last_point)
                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)
                new_line = np.concatenate([line, line_to_stripe[1:]])
                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])
            # last point match last point of other contour -> connect
            elif last_point in last_points:
                ind_to_stripe = last_points.index(last_point)
                line_to_stripe = self.index_lines.pop(ind_to_stripe)
                first_points.pop(ind_to_stripe)
                last_points.pop(ind_to_stripe)
                new_line = np.concatenate([line, line_to_stripe[::-1][1:]])
                self.index_lines.insert(line_ind, new_line)
                first_points.insert(line_ind, new_line[0])
                last_points.insert(line_ind, new_line[-1])
            else:
                self.index_lines.insert(line_ind, line)
                first_points.insert(line_ind, first_point)
                last_points.insert(line_ind, last_point)
                line_ind += 1

    def get_isoclines(self) -> List[np.ndarray]:
        """
        Get isoclines

        :return: np.ndarray(N_i, 3) for each isocline
        """
        return self.lines

    def get_index_isoclines(self) -> List[np.ndarray]:
        """
        Get isoclines

        :return: np.ndarray(N_i,) - indexes of points in model for each isocline
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
        plane_actor.GetProperty().SetColor(1.0, 1,0)
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

    def get_hills(
            self,
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
        candidates_centroids = np.asarray(candidates_centroids)

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


if __name__ == '__main__':

    import sys
    from mesh_io import read_obj_teeth
    from pathlib import Path
    from inspect import currentframe, getframeinfo
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-s", "--session",
                    action="store", dest="session_filename",
                    help="set session file path name", metavar="FILE")
    parser.add_option("-t", "--tooth_id", type="int", 
                    action="store", dest="tooth_id",
                    help="set tooth id")
    parser.add_option("-i", "--isoclines_num",
                    action="store", dest="isoclines_num", default=50,
                    help="set isoclines number")

    (options, args) = parser.parse_args()    
    #print(f' : {options} : {args}')

    # Read session configuration
    directory = Path(getframeinfo(currentframe()).filename).resolve().parents[0]

    tooth_id = options.tooth_id
    session_filename = options.session_filename
    if not session_filename:
        session_filename = directory / 'session.json'
    print(f'session filename : {session_filename}')
    
    session_config_data = json.load(open(session_filename, 'rt'))

    directory_out = session_config_data['paths']['dir_out']
    if not os.path.isabs(directory_out):
        directory_out = os.path.normpath(directory / directory_out) 
    if not os.path.exists(directory_out):
        print(f'error: out directory: {directory_out} not exists')
        exit(2)
    print(f'out directory : {directory_out}')

    upper_model_path = session_config_data['paths']['file_u']
    if not os.path.isabs(upper_model_path):
        upper_model_path = os.path.normpath(directory / upper_model_path) 
    print(f'file upper : {upper_model_path}')

    lower_model_path = session_config_data['paths']['file_l']
    if not os.path.isabs(lower_model_path):
        lower_model_path = os.path.normpath(directory / lower_model_path) 
    print(f'file lower : {lower_model_path}')   

    case_id = session_config_data['hash_for_patient_tag']
    print(f'hash_for_patient_tag : {case_id}')

    missing_id = session_config_data['missing_id']
    print(f'missing_id : {missing_id}')

    isoclines_num = 50 #options.isoclines_num
    print(f'isoclines_num : {isoclines_num}')
    
    id_mesh_dict = read_obj_teeth(
        os.path.join(directory_out, f'{case_id}_teeth.obj')
    )

    try:
        isoclines_filter = IsoclinesFilter(id_mesh_dict[tooth_id], isoclines_num=isoclines_num)
    except KeyError as exeption:
        print(f'error: tooth_id={tooth_id} is not available')
        print(f'Availabl Keys: {id_mesh_dict.keys()}')
        exit(2)
            
    isoclines_filter.export_to_pdf(
        os.path.join(
            directory_out,
            f'isoclines_{tooth_id}.pdf')
    )
    isoclines_filter.visualize_isoclines()
