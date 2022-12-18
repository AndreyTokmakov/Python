import json;
import sys
from enum import Enum, unique
from typing import Dict, List
import numpy as np
import matplotlib.pyplot as plt

POINTS_JSON_BEFORE = '/home/andtokm/Projects/CppProjects/AutoModelingTools/TreatmentPlan/data/out_before_res.json'
POINTS_JSON_AFTER = '/home/andtokm/Projects/CppProjects/AutoModelingTools/TreatmentPlan/data/out_after_res.json'

TEETH_IDS_FOR_CURVE = {11, 12, 13, 21, 22, 23  }


class Point(object):

    def __init__(self,
                 x: float = 0.0,
                 y: float = 0.0,
                 z: float = 0.0):
        self.x = x
        self.y = y
        self.z = z

    def __str__(self):
        return f'({self.x}, {self.y}, {self.z})';


# TODO: Params for parabola equation  [y = A * x*x + B * x + C]
class Coefficient(object):

    def __init__(self, a: float = 0, b: float = 0, c: float = 0):
        self.A = a
        self.B = b
        self.C = c

    def __str__(self):
        return f'(Coefficients [{self.A}, {self.B}, {self.C}])'

    def __mul__(self, other: int):
        return Coefficient(self.A * other, self.B * other, self.C * other)

    @staticmethod
    def getRandom():
        return Coefficient(a=np.random.randn(),
                           b=np.random.randn(),
                           c=np.random.randn())


def get_points_dict(file_path: str) -> Dict[int, Dict[int, Point]]:
    with open(file_path) as jsonData:
        pointsJson = json.loads(jsonData.read())

    points: Dict[int, Dict[int, Point]] = {}
    for case_number, case_points in pointsJson.items():
        points_map: Dict[int, Point] = {}
        for tooth_id, point in case_points.items():
            if 3 == len(point):
                points_map[int(tooth_id)] = Point(point[0], point[1], point[2])
        points[int(case_number)] = points_map

    return points


def case_teeth_to_numpy_array(case_teeth: Dict[int, Point]) -> np.array:
    coords = np.zeros(len(TEETH_IDS_FOR_CURVE) * 3, dtype=float)
    index: int = 0
    for tooth_id, point in case_teeth.items():
        if tooth_id in TEETH_IDS_FOR_CURVE:
            coords[index] = point.x
            coords[index + 1] = point.y  # Point::Y denotes the actual Z coordinate axis
            coords[index + 2] = point.z  # Point::Z denotes the actual Y coordinate axis
            index = index + 3
    return coords

def cases_dict_to_numpy_array(cases_dict: Dict[int, Dict[int, Point]]) -> np.array:
    result = np.zeros(shape=(0, len(TEETH_IDS_FOR_CURVE) * 3), dtype=float)
    for case_id, case_teeth in cases_dict.items():
        result = np.vstack([result, case_teeth_to_numpy_array(case_teeth)])
    return result

def cases_dict_to_numpy_array_X(cases_dict: np.array) -> np.array:
    result = np.zeros(shape=(0, len(TEETH_IDS_FOR_CURVE)), dtype=float)
    for array in cases_dict:
        i: int = 0;
        size: int = len(array);
        x_pts = []
        while size > i:
            x_pts.append(array[i])
            i = i + 3;
        result = np.vstack([result, x_pts])

    return result

def cases_dict_to_numpy_array_Y(cases_dict: np.array) -> np.array:
    result = np.zeros(shape=(0, len(TEETH_IDS_FOR_CURVE)), dtype=float)
    for array in cases_dict:
        i: int = 1;
        size: int = len(array);
        x_pts = []
        while size > i:
            x_pts.append(array[i])
            i = i + 3;
        result = np.vstack([result, x_pts])

    return result


def equation_parabola(x, coef: Coefficient) -> float:
    return coef.A * x * x + coef.B * x + coef.C

def GetParabolaCoefsFromPoints(x1, y1, x2, y2, x3, y3):
    coef = Coefficient()
    coef.A = (y3 - (x3 * (y2 - y1) + x2 * y1 - x1 * y2) / (x2 - x1)) / (x3 * (x3 - x2 - x1) + x1 * x2)
    coef.B = (y2 - y1) / (x2 - x1) - coef.A * (x1 + x2)
    coef.C = (x2 * y1 - x1 * y2) / (x2 - x1) + coef.A * x1 * x2
    return coef


def Predict():
    points_dict: Dict[int, Dict[int, Point]] = get_points_dict(POINTS_JSON_AFTER)
    points = cases_dict_to_numpy_array(points_dict)
    # points = points / np.max(points)
    np.random.shuffle(points)

    x = cases_dict_to_numpy_array_X(points)
    y = cases_dict_to_numpy_array_Y(points)

    coef = Coefficient.getRandom()
    print(coef)

    K: float = 2.0
    EPOCHS_MINIMUM = 1000;
    LEARNING_RATE: float = 1e-9

    counter = 0
    for t in range(100_000_000):
        diff = equation_parabola(x, coef) - y
        loss: float = np.square(diff).sum()

        # print(f'predicted: {predicted}')
        # print(f'actual   : {y}')

        if counter % 10_000 == 0:
            print(counter, loss)
            print(f'Predictions: [{coef}]')

        grad_y_pred = K * diff
        grad_c = grad_y_pred.sum()
        grad_b = (grad_y_pred * x).sum()
        grad_a = (grad_y_pred * x * x).sum()

        # Update weights
        coef.A -= LEARNING_RATE * grad_a
        coef.B -= LEARNING_RATE * grad_b
        coef.C -= LEARNING_RATE * grad_c

        counter = counter + 1
        if 4.5 > loss and t > EPOCHS_MINIMUM:
            break;

    print(f'Predictions: [{coef}]')
    print(f'loss: [{loss}]')
    print(f'counter: [{counter}]')

def Visualize():
    points_dict: Dict[int, Dict[int, Point]] = get_points_dict(POINTS_JSON_AFTER)

    for case_id, teeth_map in points_dict.items():
        x = [pt.x for k, pt in teeth_map.items()]
        y = [pt.y for k, pt in teeth_map.items()]

        plt.scatter(x, y)
        plt.show()


def Visualize_Numpy():
    points_dict: Dict[int, Dict[int, Point]] = get_points_dict(POINTS_JSON_AFTER)
    points = cases_dict_to_numpy_array(points_dict)
    points = points / np.max(points)

    x = cases_dict_to_numpy_array_X(points)
    y = cases_dict_to_numpy_array_Y(points)

    for i in range(len(x)):
        plt.scatter(x[i], y[i])
        plt.show()
        if i > 10:
            break

def Visualize_Parabola_ByPoints_And_Coefficients():
    points_dict: Dict[int, Dict[int, Point]] = get_points_dict(POINTS_JSON_AFTER)
    points = cases_dict_to_numpy_array(points_dict)
    np.random.shuffle(points)

    x = cases_dict_to_numpy_array_X(points)[0]
    y = cases_dict_to_numpy_array_Y(points)[0]
    plt.scatter(x, y)
    plt.show()


    coef = GetParabolaCoefsFromPoints(x[0], y[0], x[3], y[3], x[7], y[7])
    print(coef)
    y = equation_parabola(x, coef)
    plt.scatter(x, y)
    plt.show()


    coef = Coefficient(-0.03065775028732241, -0.001127238341818489, 22.309923007969807)
    print(coef)
    y = equation_parabola(x, coef)
    plt.scatter(x, y)
    plt.show()





def Get_Coefficients():
    points_dict: Dict[int, Dict[int, Point]] = get_points_dict(POINTS_JSON_AFTER)
    points = cases_dict_to_numpy_array(points_dict)

    x = cases_dict_to_numpy_array_X(points)
    y = cases_dict_to_numpy_array_Y(points)

    for i in range(len(x)):
        coef = GetParabolaCoefsFromPoints(x[i][0], y[i][0], x[i][3], y[i][3], x[i][7], y[i][7])
        print(coef)



if __name__ == '__main__':
    Predict()

# Visualize()
# Visualize_Numpy()
# Visualize_Parabola_ByPoints_And_Coefficients();

# Get_Coefficients()













