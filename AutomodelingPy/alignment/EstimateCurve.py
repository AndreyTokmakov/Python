import math
import sys
from collections import namedtuple

import numpy as np
from typing import Dict, List, Tuple, Callable
from vtkmodules.vtkCommonDataModel import vtkPolyData, vtkPlane, vtkDataObject
from vtkmodules.vtkCommonMath import vtkMatrix4x4
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersCore import vtkCutter
from vtkmodules.vtkFiltersGeneral import vtkTransformPolyDataFilter, vtkIntersectionPolyDataFilter, \
    vtkDistancePolyDataFilter
from vtkmodules.vtkRenderingCore import vtkActor

from AutomodelingPy.geometry.Line2D import Line2D
from AutomodelingPy.geometry.Point2D import Point2D
from AutomodelingPy.model.FDI import FDI
from AutomodelingPy.model.Tooth import Tooth
from AutomodelingPy.utils.Utilities import Utilities
from AutomodelingPy.utils.Transformation import TransformationData, ToothTransformation


class VisUtils(object):
    @staticmethod
    def DisplayTeeth(teeth: Dict[int, Tooth],
                     ids: List[int],
                     name: str = "VTK Window",
                     segments: Dict[int, Line2D] = None,
                     yOffset: int = 5):
        actors: List[vtkActor] = []
        for idx in ids:
            tooth: Tooth = teeth[idx]
            actors.append(Utilities.getPolyDataActor(tooth.data))

        if segments:
            for _, line in segments.items():
                actors.append(
                    Utilities.getLineActor([line.pt1.x, yOffset, line.pt1.y], [line.pt2.x, yOffset, line.pt2.y]))
                actors.append(Utilities.getPointsActor([[line.pt1.x, yOffset, line.pt1.y],
                                                        [line.pt2.x, yOffset, line.pt2.y]], size=8))

        for a in actors:
            a.RotateX(90)
            a.RotateY(180)
        Utilities.DisplayActors(actors, windowName=name)

    @staticmethod
    def DisplaySegments(segments1: Dict[int, Line2D],
                        segments2: Dict[int, Line2D] = None,
                        name: str = "VTK Window",
                        yOffset: int = 5):
        actors: List[vtkActor] = []
        for _, line in segments1.items():
            actors.append(Utilities.getLineActor([line.pt1.x, yOffset, line.pt1.y], [line.pt2.x, yOffset, line.pt2.y]))
            actors.append(Utilities.getPointsActor([[line.pt1.x, yOffset, line.pt1.y],
                                                    [line.pt2.x, yOffset, line.pt2.y]], size=8))

        if segments2:
            for _, line in segments2.items():
                actors.append(Utilities.getLineActor([line.pt1.x, yOffset, line.pt1.y],
                                                     [line.pt2.x, yOffset, line.pt2.y], color=[1, 1, 0]))
                actors.append(Utilities.getPointsActor([[line.pt1.x, yOffset, line.pt1.y],
                                                        [line.pt2.x, yOffset, line.pt2.y]], size=8))

        for a in actors:
            a.RotateX(90)
            a.RotateY(180)
        Utilities.DisplayActors(actors, windowName=name)


class ControlPoints(object):
    center: Point2D = Point2D(0.0, 0.0)
    leftMolar: Point2D = Point2D(0.0, 0.0)
    leftFang: Point2D = Point2D(0.0, 0.0)
    rightMolar: Point2D = Point2D(0.0, 0.0)
    rightFang: Point2D = Point2D(0.0, 0.0)

    # Sum ControlPoints += Point2D
    def __iadd__(self, other: Point2D):
        ctrl_pt: ControlPoints = ControlPoints()

        ctrl_pt.center = self.center + other
        ctrl_pt.leftMolar = self.leftMolar + other
        ctrl_pt.leftFang = self.leftFang + other
        ctrl_pt.rightMolar = self.rightMolar + other
        ctrl_pt.rightFang = self.rightFang + other

        return ctrl_pt

    # Sum ControlPoints -= Point2D
    def __isub__(self, other: Point2D):
        ctrl_pt: ControlPoints = ControlPoints()

        ctrl_pt.center = self.center - other
        ctrl_pt.leftMolar = self.leftMolar - other
        ctrl_pt.leftFang = self.leftFang - other
        ctrl_pt.rightMolar = self.rightMolar - other
        ctrl_pt.rightFang = self.rightFang - other

        return ctrl_pt


class Params(object):
    xLeftMolarMove: float = 0
    xLeftFangMove: float = 0
    xRightMolarMove: float = 0
    xRightFangMove: float = 0
    yTop: float = 0


class CurveParams(object):
    slopeLeft: float = 0
    interceptLeft: float = 0
    slopeRight: float = 0
    interceptRight: float = 0
    yRadius: float = 0
    xRadiusLeft: float = 0
    xRadiusRight: float = 0

    def ellipseLeft(self, x: float) -> float:
        if abs(x) > self.xRadiusLeft:
            return 0
        return math.sqrt((self.yRadius * self.yRadius) * (1 - (x * x) /
                                                          (self.xRadiusLeft * self.xRadiusLeft)))

    def ellipseRight(self, x: float) -> float:
        if abs(x) > self.xRadiusRight:
            return 0
        return math.sqrt((self.yRadius * self.yRadius) * (1 - (x * x) /
                                                          (self.xRadiusRight * self.xRadiusRight)))

    def curveFunction(self, x: float, tooth_id: int, pt: Point2D = None) -> float:
        if (tooth_id % 10) > 3:
            return (x * self.slopeRight + self.interceptRight) if (x > 0) else (x * self.slopeLeft + self.interceptLeft)
        else:
            return self.ellipseRight(x) if (x > 0) else self.ellipseLeft(x)


class EstimateCurve(object):
    LOWER_TEETH: List[int] = [47, 46, 45, 44, 43, 42, 41,
                              31, 32, 33, 34, 35, 36, 37]

    @staticmethod
    def midpoint(pt1: List, pt2: List) -> List:
        return list(map(lambda coords: (coords[0] + coords[1]) / 2, zip(pt1, pt2)))

    @staticmethod
    def get_control_points(segments: Dict[int, Line2D]) -> ControlPoints:
        pts: ControlPoints = ControlPoints()

        pts.center = Point2D((segments[31].pt1.x + segments[41].pt1.x) / 2,
                             (segments[31].pt1.y + segments[41].pt1.y) / 2)
        pts.leftMolar = segments[47].pt2.clone()
        pts.leftFang = segments[43].pt2.clone()
        pts.rightMolar = segments[37].pt2.clone()
        pts.rightFang = segments[33].pt2.clone()

        pts.leftMolar.x -= pts.center.x
        pts.leftFang.x -= pts.center.x
        pts.rightMolar.x -= pts.center.x
        pts.rightFang.x -= pts.center.x
        pts.center.x -= pts.center.x

        return pts

    @staticmethod
    def transformVtkData(polyData: vtkPolyData, matrix: vtkMatrix4x4):
        transform: vtkTransform = vtkTransform()
        transform.SetMatrix(matrix)

        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
        transformFilter.Update()

        return transformFilter.GetOutput()

    @staticmethod
    def hasIntersection(data1: vtkPolyData, data2: vtkPolyData) -> bool:
        booleanFilter: vtkIntersectionPolyDataFilter = vtkIntersectionPolyDataFilter()
        booleanFilter.GlobalWarningDisplayOff()
        booleanFilter.SetInputData(0, data1)
        booleanFilter.SetInputData(1, data2)
        booleanFilter.Update()

        return booleanFilter.GetNumberOfIntersectionPoints() > 0

    @staticmethod
    def getDistance(data1: vtkPolyData, data2: vtkPolyData) -> float:
        distance_filter: vtkDistancePolyDataFilter = vtkDistancePolyDataFilter()
        distance_filter.SetInputData(0, data1)
        distance_filter.SetInputData(1, data2)
        distance_filter.SignedDistanceOff()
        distance_filter.ComputeSecondDistanceOn()
        distance_filter.Update()

        distMin: float = sys.float_info.max
        for distArray in [distance_filter.GetOutput().GetPointData().GetScalars(),
                          distance_filter.GetOutput().GetCellData().GetScalars(),
                          distance_filter.GetSecondDistanceOutput().GetPointData().GetScalars(),
                          distance_filter.GetSecondDistanceOutput().GetCellData().GetScalars()]:
            size: int = distArray.GetNumberOfValues()
            for idx in range(0, size):
                dist: float = distArray.GetTuple(idx)[0]
                distMin = min(dist, distMin)

        return distMin

    @staticmethod
    def getTeethSegments(teeth: Dict[int, Tooth],
                         teeth_ids: List[int]) -> Dict[int, Line2D]:
        segments: Dict[int, Line2D] = dict()
        for tooth_id in teeth_ids:
            tooth: Tooth = teeth.get(tooth_id)
            center, bounds = tooth.getCenter(), tooth.getBounds()
            start, end = center - tooth.xAxis, center + tooth.xAxis

            slopeY, interceptY = Utilities.get_line_coefficients([start[0], start[1]], [end[0], end[1]])
            slopeZ, interceptZ = Utilities.get_line_coefficients([start[0], start[2]], [end[0], end[2]])

            segLength: float = Utilities.distance_between_two_points(start, end)
            ratio, xDist = tooth.width / segLength, abs(start[0] - end[0])

            start[0] = center[0] - ratio * xDist / 2
            end[0] = center[0] + ratio * xDist / 2
            start[1] = start[0] * slopeY + interceptY
            end[1] = end[0] * slopeY + interceptY
            start[2] = start[0] * slopeZ + interceptZ
            end[2] = end[0] * slopeZ + interceptZ

            if 4 >= (tooth_id % 10):  # Only for first 5 teeth
                cutSize: float = 1.0
                midPoint = EstimateCurve.midpoint(start, end)
                centerNew = center.copy()
                centerNew[1] = bounds[3] - cutSize if FDI.isLowerTooth(tooth_id) else bounds[2] + cutSize

                plane: vtkPlane = vtkPlane()
                plane.SetOrigin(centerNew)
                plane.SetNormal(tooth.yAxis)

                cutter: vtkCutter = vtkCutter()
                cutter.SetCutFunction(plane)
                cutter.SetInputData(tooth.data)
                cutter.Update()
                cutterData = cutter.GetOutput()

                bnds: np.ndarray = np.asarray(cutterData.GetBounds())
                cuttingEdge = np.asarray([(bnds[0] + bnds[1]) / 2, (bnds[2] + bnds[3]) / 2, (bnds[4] + bnds[5]) / 2])

                start += (cuttingEdge - midPoint)
                end += (cuttingEdge - midPoint)

            line: Line2D = Line2D(Point2D(start[0], start[2]), Point2D(end[0], end[2]))

            # Ensure that the segments are arranged so that:
            # 1. For the left  teeth of the jaw the X coordinate of Point1 of the line is greater than X of Point2
            # 2. For the right teeth of the jaw the X coordinate of Point1 of the line is less    than X of Point2
            # As a result, Point1 of the segment is always located closer to the center of the jaw than Point2
            if FDI.isLeftSideTooth(tooth_id) and line.pt1.x > line.pt2.x:
                line.swapPoints()
            elif FDI.isRightSideTooth(tooth_id) and line.pt2.x > line.pt1.x:
                line.swapPoints()
            segments[tooth_id] = line

        return segments

    @staticmethod
    def place_segment_on_curve(line: Line2D,
                               tooth_id: int,
                               dest: Point2D,
                               func: Callable) -> Tuple[bool, float]:
        line.setPoint1(dest.clone())
        outer: bool = func(line.pt2.x, tooth_id % 10, dest) > line.pt2.y
        direction: float = -1.0 if outer else 1.0  # TODO: to once condition
        direction *= 1.0 if FDI.isRightSideTooth(tooth_id) else -1.0  # TODO: to once condition

        angle: float = 0
        for i in range(0, 45):
            line.rotateAroundPoint1(direction)
            if 0 > line.pt2.y:
                return False, 0
            yLine, yCurve = line.pt2.y, func(line.pt2.x, tooth_id % 10, dest)
            if (outer and yLine >= yCurve) or (False == outer and yCurve >= yLine):
                break
            angle = i

        return True, direction * angle

    @staticmethod
    def estimate(teeth: Dict[int, Tooth],
                 transformation: TransformationData) -> None:

        leftMolarBounds: np.ndarray = teeth[37].getBounds()
        rightMolarBounds: np.ndarray = teeth[47].getBounds()
        leftMolarCenter: np.ndarray = teeth[37].getCenter()
        rightMolarCenter: np.ndarray = teeth[47].getCenter()

        if leftMolarCenter[0] > rightMolarCenter[0]:
            rightMolarBounds, leftMolarBounds, = leftMolarBounds, rightMolarBounds

        zBack: float = min([leftMolarBounds[4], leftMolarBounds[5], rightMolarBounds[4], rightMolarBounds[5]])

        # TODO: zBack ??? Remove / Refactor??
        segments: Dict[int, Line2D] = EstimateCurve.getTeethSegments(teeth, EstimateCurve.LOWER_TEETH)
        ptCenter: Point2D = Point2D((segments[31].pt1.x + segments[41].pt1.x) / 2, zBack)

        controlPoints: ControlPoints = EstimateCurve.get_control_points(segments)
        controlPoints -= Point2D(0, zBack)

        teethCopy: Dict[int, Tooth] = dict()
        for tooth_id in EstimateCurve.LOWER_TEETH:
            tooth: Tooth = teeth.get(tooth_id)
            tooth.data = Utilities.moveTooth(tooth.data, -ptCenter.x, 0, -zBack)
            segments[tooth_id] -= ptCenter
            teethCopy[tooth_id] = tooth.copy()

        VisUtils.DisplayTeeth(teeth, EstimateCurve.LOWER_TEETH, "Teeth 1", segments)
        # VisUtils.DisplayTeeth(teethCopy, EstimateCurve.LOWER_TEETH, "TeethCopy 1", segments)
        # return

        params: Params = Params()
        curveParams: CurveParams = CurveParams()

        def curveFunction(x: float, tooth_id: int, pt=None) -> float:
            return curveParams.curveFunction(x, tooth_id)

        # TODO: Add detailed description
        def updateCurveParamsFromPoints():
            curveParams.yRadius = controlPoints.center.y + params.yTop
            curveParams.xRadiusLeft = math.sqrt(math.pow(controlPoints.leftFang.x + params.xLeftFangMove, 2) /
                                                (1 - math.pow(controlPoints.leftFang.y, 2) / (
                                                        curveParams.yRadius * curveParams.yRadius)))
            curveParams.xRadiusRight = math.sqrt(math.pow(controlPoints.rightFang.x + params.xRightFangMove, 2) /
                                                 (1 - math.pow(controlPoints.rightFang.y, 2) / (
                                                         curveParams.yRadius * curveParams.yRadius)))
            curveParams.slopeLeft, curveParams.interceptLeft = Utilities.get_line_coefficients(
                [controlPoints.leftMolar.x + params.xLeftMolarMove, controlPoints.leftMolar.y],
                [controlPoints.leftFang.x + params.xLeftFangMove, controlPoints.leftFang.y])
            curveParams.slopeRight, curveParams.interceptRight = Utilities.get_line_coefficients(
                [controlPoints.rightMolar.x + params.xRightMolarMove, controlPoints.rightMolar.y],
                [controlPoints.rightFang.x + params.xRightFangMove, controlPoints.rightFang.y])

        def absApproxGreater(a: float, b: float, delta: float) -> bool:
            return (abs(a) - abs(b)) >= delta

        # TODO: Use Pont/Korkhause coefficients
        incisorsMoveLimit: float = 2.0  # FIXME: Check only Y movements?
        molarMoveLimit: float = 2.0
        premolarMoveLimit: float = 3.0
        step: float = 0.01

        # TODO: Refactor??
        def getLimitForTooth(tooth_id: int) -> float:
            t_id: int = tooth_id % 10
            if 1 == t_id or 2 == t_id:
                return incisorsMoveLimit
            elif 3 == t_id or 4 == t_id or 5 == t_id:
                return premolarMoveLimit
            else:
                return molarMoveLimit

        # TODO: Use class instead of namedtuple
        class SegmentTransform(object):
            def __init__(self, pt: Point2D, a: float):
                self.point: Point2D = pt
                self.angle: float = a

            def clone(self):
                return SegmentTransform(self.point.clone(), self.angle)

        satisfyTheLimits, isFitted = False, False
        segmentsFinal: Dict[int, Line2D] = dict()
        transformFinal: Dict[int, SegmentTransform] = dict()
        while True:
            while premolarMoveLimit > params.xRightFangMove or not (satisfyTheLimits and isFitted):
                if absApproxGreater(controlPoints.leftFang.x + params.xLeftFangMove,
                                    controlPoints.rightFang.x + params.xRightFangMove, 0.01):
                    params.xRightFangMove += step
                elif absApproxGreater(controlPoints.rightFang.x + params.xRightFangMove,
                                      controlPoints.leftFang.x + params.xLeftFangMove, 0.01):
                    params.xLeftFangMove -= step
                else:
                    params.xLeftFangMove -= step
                    params.xRightFangMove += step

                updateCurveParamsFromPoints()

                isFitted, satisfyTheLimits = True, True
                for i in [30, 40]:
                    dest: Point2D = Point2D(0, curveParams.curveFunction(0, 0))
                    if not satisfyTheLimits or not isFitted:
                        break
                    for tooth_id in range(1 + i, 8 + i):
                        segmentsFinal[tooth_id] = segments[tooth_id].clone()
                        line: Line2D = segmentsFinal[tooth_id]
                        isFitted, angle = EstimateCurve.place_segment_on_curve(line, tooth_id, dest, curveFunction)
                        dest = line.pt2.clone()
                        if not isFitted:
                            break

                        transformFinal[tooth_id] = SegmentTransform(line.getMidPoint(), angle)
                        dist = segments[tooth_id].getDistanceBetweenCenters(line)
                        moveLimit = getLimitForTooth(tooth_id)
                        if dist > moveLimit:
                            satisfyTheLimits = False
                            break

            if isFitted and satisfyTheLimits:
                break

            params.xRightFangMove, params.xLeftFangMove = 0, 0
            if molarMoveLimit > abs(params.xLeftMolarMove) and molarMoveLimit > abs(params.xRightMolarMove):
                params.xLeftMolarMove -= step
                params.xRightMolarMove += step
            else:
                if params.yTop > incisorsMoveLimit and isFitted and satisfyTheLimits:
                    break
                params.yTop += step

        VisUtils.DisplaySegments(segments, segmentsFinal)

        # Place teeth on predicted curve:
        for i in [30, 40]:
            for tooth_id in range(1 + i, 8 + i):
                tooth: Tooth = teeth.get(tooth_id)
                tooth_transformation: ToothTransformation = transformation.teethTransform[tooth_id]
                centerOrigin: Point2D = segments[tooth_id].getMidPoint().clone()
                centerDest: Point2D = transformFinal[tooth_id].point.clone()
                angle: float = transformFinal[tooth_id].angle
                move: Point2D = centerDest - centerOrigin
                origin: np.ndarray = tooth.getCenter()

                transform: vtkTransform = vtkTransform()
                transform.PostMultiply()
                transform.Translate(-origin)
                transform.RotateWXYZ(-angle, 0, 1, 0)
                transform.Translate(origin)
                transform.Translate(move.x, 0, move.y)

                tooth.data = EstimateCurve.transformVtkData(tooth.data, transform.GetMatrix())
                tooth_transformation.curveSetUp = transform.GetMatrix()

        def applyTransformation(tooth_id: int,
                                toothData: vtkPolyData) -> vtkPolyData:
            # mv: Point2D = transformFinal.get(tooth_id).point - segmentsFinal.get(tooth_id).getMidPoint()
            toothTransform: SegmentTransform = transformFinal.get(tooth_id)
            centerOrigin: Point2D = segmentsFinal.get(tooth_id).getMidPoint()
            move: Point2D = toothTransform.point - centerOrigin

            data: vtkPolyData = vtkPolyData()
            data.DeepCopy(toothData)

            orig: np.ndarray = np.asarray(data.GetCenter())

            data = Utilities.setPolyDataCenter(data, 0, 0, 0)
            data = Utilities.rotatePolyData(data, 0, -toothTransform.angle, 0)
            data = Utilities.setPolyDataCenter(data, orig[0], orig[1], orig[2])
            return Utilities.moveTooth(data, move.x, 0, move.y)

        def moveSegment(tooth_id: int,
                        xStep: float) -> None:
            transformation: SegmentTransform = transformFinal.get(tooth_id)
            if tooth_id % 10 > 3:
                pt1: Point2D = segmentsFinal.get(tooth_id).getMidPoint()
                transformation.point.y = pt1.y + xStep
                if not FDI.isLeftSideTooth(tooth_id):
                    transformation.point.x = (transformation.point.y - curveParams.interceptLeft) / curveParams.slopeLeft
                else:
                    transformation.point.x = (transformation.point.y - curveParams.interceptRight) / curveParams.slopeRight
            else:
                line: Line2D = segmentsFinal.get(tooth_id).clone()
                dest: Point2D = Point2D(line.pt1.x + xStep, curveParams.curveFunction(line.pt1.x + xStep, tooth_id))
                _, angle = EstimateCurve.place_segment_on_curve(line, tooth_id, dest, curveFunction)
                transformation.point = line.getMidPoint()
                transformation.angle = angle

        transformFinalOriginal: Dict[int, SegmentTransform] = {k: v.clone() for k, v in transformFinal.items()}
        stepSize: float = 0.01

        for id1, id2 in [[31, 41]]:
            print(f'[{id1} - {id2}]')
            toothLeft, toothRight = teeth.get(id1).data, teeth.get(id2).data
            isIntersectedBefore: bool = EstimateCurve.hasIntersection(toothLeft, toothRight)
            deltaStep: float = stepSize * (1 if isIntersectedBefore else -1)
            stepLeft, stepRight = 0.0, 0.0

            movedToothLeft, movedToothRight = vtkPolyData(), vtkPolyData()
            while True:
                stepLeft += deltaStep
                stepRight -= deltaStep
                moveSegment(id1, stepLeft)
                moveSegment(id2, stepRight)
                movedToothLeft = applyTransformation(id1, toothLeft)
                movedToothRight = applyTransformation(id2, toothRight)
                isIntersectedNow: bool = EstimateCurve.hasIntersection(movedToothLeft, movedToothRight)

                if isIntersectedBefore and not isIntersectedNow:
                    break
                elif isIntersectedNow and not isIntersectedBefore:
                    stepLeft -= deltaStep
                    stepRight += deltaStep
                    moveSegment(id1, stepLeft)
                    moveSegment(id2, stepRight)
                    movedToothLeft = applyTransformation(id1, toothLeft)
                    movedToothRight = applyTransformation(id2, toothRight)
                    break

            toothLeft.DeepCopy(movedToothLeft)
            toothRight.DeepCopy(movedToothRight)

        def collisionRemove(ids: List[int], stepSize: float):
            for id1, id2 in zip(ids, ids[1:]):
                print(f'[{id1} - {id2}]')
                dir: int = -1 if (
                            segmentsFinal.get(id2).getMidPoint().x > segmentsFinal.get(id1).getMidPoint().x) else 1
                toothDest, toothToMove = teeth.get(id1).data, teeth.get(id2).data
                dist: float = EstimateCurve.getDistance(toothDest, toothToMove)
                isIntersectedBefore: bool = EstimateCurve.hasIntersection(toothDest, toothToMove) and 0.05 > dist
                deltaStep: float = stepSize * dir * (-1 if isIntersectedBefore else 1)
                stepTotal: float = 0.0
                if id2 % 10 > 3:
                    deltaStep = -stepSize if isIntersectedBefore else stepSize

                movedTooth: vtkPolyData = vtkPolyData()
                repeatCount: int = 0
                while 6 > repeatCount:
                    repeatCount += 1
                    while True:
                        stepTotal += deltaStep
                        moveSegment(id2, stepTotal)
                        movedTooth = applyTransformation(id2, toothToMove)
                        intersected: bool = EstimateCurve.hasIntersection(toothDest, movedTooth)

                        if isIntersectedBefore and not intersected:
                            break
                        elif intersected and not isIntersectedBefore:
                            stepTotal -= deltaStep
                            moveSegment(id2, stepTotal)
                            movedTooth = applyTransformation(id2, toothToMove)
                            break

                    if EstimateCurve.hasIntersection(toothDest, movedTooth):
                        continue

                    dist = EstimateCurve.getDistance(toothDest, movedTooth)
                    if 0.01 <= dist <= 0.05:
                        break

                toothToMove.DeepCopy(movedTooth)

        collisionRemove(ids=[41, 42, 43, 44, 45, 46, 47], stepSize=0.03)
        collisionRemove(ids=[31, 32, 33, 34, 35, 36, 37], stepSize=0.03)

        for i in [30, 40]:
            for tooth_id in range(1 + i, 8 + i):
                tooth: Tooth = teethCopy.get(tooth_id)
                original, destination = transformFinalOriginal.get(tooth_id), transformFinal.get(tooth_id)
                move: Point2D = destination.point - original.point
                center: np.ndarray = tooth.getCenter()

                transform: vtkTransform = vtkTransform()
                transform.PostMultiply()
                transform.Translate(-center)
                transform.RotateWXYZ(-destination.angle, 0, 1, 0)
                transform.Translate(center)
                transform.Translate(move.x, 0, move.y)

                tooth_transformation: ToothTransformation = transformation.teethTransform[tooth_id]
                vtkMatrix4x4.Multiply4x4(transform.GetMatrix(),
                                         tooth_transformation.curveSetUp,
                                         tooth_transformation.curveSetUp)

        for i in [30, 40]:
            for tooth_id in range(1 + i, 8 + i):
                tooth: Tooth = teethCopy.get(tooth_id)
                tooth_transformation: ToothTransformation = transformation.teethTransform[tooth_id]
                tooth.data = EstimateCurve.transformVtkData(tooth.data, tooth_transformation.curveSetUp)

        VisUtils.DisplayTeeth(teeth, EstimateCurve.LOWER_TEETH, "Final", segmentsFinal)
        VisUtils.DisplayTeeth(teethCopy, EstimateCurve.LOWER_TEETH, "Final (Copy)", segmentsFinal)
