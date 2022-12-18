from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkFiltersGeneral import vtkCurvatures, vtkCellDerivatives
from vtkmodules.vtkIOLegacy import vtkPolyDataWriter

from VTK_Experiments.Utilities import Utilities


STL_FILE = '/home/andtokm/Projects/data/out/Tooths/tooth_11.stl'

def Mean():
    data: vtkPolyData = Utilities.readStl(STL_FILE)
    #Utilities.visualize(data)

    curv: vtkCurvatures = vtkCurvatures()
    curv.SetInputData(data)
    # curv.SetCurvatureTypeToGaussian()
    curv.SetCurvatureTypeToMean()
    curv.Update()
    pd = curv.GetOutput()

    for i in range(pd.GetPointData().GetNumberOfArrays()):
        print(pd.GetPointData().GetArrayName(i))
    # This will print the following:
    # PointIds
    # PointNormals
    # Gauss_Curvature

    # To set the active scalar to Gauss_Curvature
    pd.GetPointData().SetActiveScalars('Mean_Curvature')

    curvdiff = vtkCellDerivatives()
    curvdiff.SetInputData(pd)
    curvdiff.SetVectorModeToComputeGradient()
    curvdiff.Update()

    Utilities.visualize(curvdiff.GetOutput())

def Gauss():
    data: vtkPolyData = Utilities.readStl(STL_FILE)

    curv: vtkCurvatures = vtkCurvatures()
    curv.SetInputData(data)
    curv.SetCurvatureTypeToGaussian()
    curv.Update()
    pd = curv.GetOutput()

    for i in range(pd.GetPointData().GetNumberOfArrays()):
        print(pd.GetPointData().GetArrayName(i))


    # To set the active scalar to Gauss_Curvature
    pd.GetPointData().SetActiveScalars('Gauss_Curvature')

    curvdiff = vtkCellDerivatives()
    curvdiff.SetInputData(pd)
    curvdiff.SetVectorModeToComputeGradient()
    curvdiff.Update()

    Utilities.visualize(curvdiff.GetOutput())


if __name__ == '__main__':
    Mean()
    # Gauss()
