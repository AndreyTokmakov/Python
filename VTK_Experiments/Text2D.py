from vtkmodules.vtkCommonColor import vtkNamedColors
from vtkmodules.vtkRenderingCore import vtkTextActor, vtkRenderer, vtkRenderWindow, vtkRenderWindowInteractor, vtkActor

from VTK_Experiments.Types import Point3D
from VTK_Experiments.Utilities import Utilities

if __name__ == '__main__':
    colors: vtkNamedColors = vtkNamedColors()
    windowName = "VTK Window"


    textActor: vtkTextActor = vtkTextActor()
    textActor.SetInput('Text')
    textActor.SetPosition(10, 10)
    textActor.GetTextProperty().SetFontSize(64)
    textActor.GetTextProperty().SetColor(1,1,1)

    pts = [Point3D(1, 2, 0), Point3D(2, 3, 0), Point3D(3, 4, 0)]
    actor: vtkActor = Utilities.getPointsActor(pts)
    Utilities.DisplayActors([actor, textActor])