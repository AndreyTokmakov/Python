from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkCommonTransforms import vtkTransform
from vtkmodules.vtkFiltersGeneral import vtkOBBTree, vtkTransformPolyDataFilter

from VTK_Experiments.Utilities import Utilities


def BoundingBox():
    STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'
    polyData: vtkPolyData = Utilities.readStl(STL_FILE)
    Utilities.visualize(polyData, True)


def OrientedBoundingBOx():
    STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'
    polyData: vtkPolyData = Utilities.readStl(STL_FILE)

    obbTree = vtkOBBTree()
    obbTree.SetDataSet(polyData)
    obbTree.SetMaxLevel(1)
    obbTree.BuildLocator()

    pd: vtkPolyData = vtkPolyData()
    obbTree.GenerateRepresentation(0, pd);

    actor = Utilities.getPolyDataActor(pd)
    actor.GetProperty().SetOpacity(.5);

    Utilities.DisplayActors([actor])

def RotateAndCalcNewBox():
    # STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'
    STL_FILE = '/home/andtokm/Projects/data/out/Tooths/tooth_5.stl'
    polyData: vtkPolyData = Utilities.readStl(STL_FILE)

    for i in range(45):
        transform: vtkTransform = vtkTransform()
        transformFilter: vtkTransformPolyDataFilter = vtkTransformPolyDataFilter()
        # transform.RotateY(i * (180 / 18))
        transform.RotateZ(i * -10)

        transformFilter.SetInputData(polyData)
        transformFilter.SetTransform(transform)
        transformFilter.Update()
        pd = transformFilter.GetOutput()

        Utilities.visualize(pd, True)

        '''
        toothActor = Utilities.getPolyDataActor(pd)

        obbTree = vtkOBBTree()
        obbTree.SetDataSet(pd)
        obbTree.SetMaxLevel(2)
        obbTree.BuildLocator()

        pd: vtkPolyData = vtkPolyData()
        obbTree.GenerateRepresentation(0, pd);

        actor = Utilities.getPolyDataActor(pd)
        actor.GetProperty().SetOpacity(.3);

        Utilities.DisplayActors([toothActor, actor])
        '''




if __name__ == '__main__':
    # BoundingBox()
    # OrientedBoundingBOx()
    RotateAndCalcNewBox()
