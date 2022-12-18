
import os
from pathlib import Path

BASE_DIR_PATH = "S:\\Temp\\Folder_For_Testing";
DIR_TO_CREATE = BASE_DIR_PATH + "\\Dir3"

def MakeDir():
    try:
        os.mkdir(DIR_TO_CREATE)
    except FileExistsError as exc:
        print(exc)
        
def MakeDir_Pathlib():
    p = Path(DIR_TO_CREATE)
    try:
        p.mkdir()
    except FileExistsError as exc:
        print(exc)
        print("Force creating dir 'exist_ok=True'");
        p.mkdir(exist_ok=True)
        print("OK");
        
        
def CreatingMultipleDirectories():
    os.makedirs(BASE_DIR_PATH + "\\Dir3\\Dir2\\Dir1")
    
def CreatingMultipleDirectories_AccessAttributes():
    os.makedirs(BASE_DIR_PATH + "\\Dir4\\Dir2\\Dir1", mode=0o770)

##################################################
if __name__ == '__main__':
    # MakeDir();
    # MakeDir_Pathlib();
    # CreatingMultipleDirectories();
    CreatingMultipleDirectories_AccessAttributes();