# noinspection PyUnresolvedReferences
import vtkmodules.vtkInteractionStyle
# noinspection PyUnresolvedReferences
import vtkmodules.vtkRenderingOpenGL2
from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkCommonDataModel import vtkPolyData
from vtkmodules.vtkFiltersCore import vtkFeatureEdges
from vtkmodules.vtkFiltersModeling import vtkOutlineFilter
from vtkmodules.vtkFiltersSources import vtkDiskSource
from vtkmodules.vtkRenderingCore import (
    vtkActor,
    vtkPolyDataMapper,
    vtkRenderWindow,
    vtkRenderWindowInteractor,
    vtkRenderer
)

from VTK_Experiments.Utilities import Utilities


def Mark_Borders():
    colors = vtkNamedColors()
    diskSource = vtkDiskSource()
    diskSource.Update()

    featureEdges = vtkFeatureEdges()
    featureEdges.SetInputConnection(diskSource.GetOutputPort())
    featureEdges.BoundaryEdgesOn()
    featureEdges.FeatureEdgesOff()
    featureEdges.ManifoldEdgesOff()
    featureEdges.NonManifoldEdgesOff()
    featureEdges.ColoringOn()
    featureEdges.Update()

    # Visualize
    edgeMapper = vtkPolyDataMapper()
    edgeMapper.SetInputConnection(featureEdges.GetOutputPort())
    edgeActor = vtkActor()
    edgeActor.SetMapper(edgeMapper)

    diskMapper = vtkPolyDataMapper()
    diskMapper.SetInputConnection(diskSource.GetOutputPort())
    diskActor = vtkActor()
    diskActor.SetMapper(diskMapper)
    diskActor.GetProperty().SetColor(colors.GetColor3d('Gray'))

    Utilities.DisplayActors([diskActor, edgeActor])

def BoundingBox():
    STL_FILE = '/home/andtokm/Projects/data/cases/2280/automodeling/crowns/2280_lower.stl'

    polyData: vtkPolyData = Utilities.readStl(STL_FILE)
    Utilities.visualize(polyData, True)


if __name__ == '__main__':
    Mark_Borders()
    # BoundingBox()