
import os
from pathlib import Path

if __name__ == '__main__':

    # Get the current directory path
    current_directory = os.getcwd()
    print("Current working directory:", current_directory)

    # Get the script path and the file name
    foldername = os.path.basename(current_directory)

    scriptpath = os.path.realpath(__file__)
    print(type(scriptpath))

    scriptParent = Path(scriptpath).parent.absolute().joinpath("23332")
    print(scriptParent)