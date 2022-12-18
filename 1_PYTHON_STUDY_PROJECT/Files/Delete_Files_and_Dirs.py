
import os
import shutil
from pathlib import Path

DIR_PATH = "S:\\Temp\\Folder_For_Testing\\DELETE";
FILE_TO_DELETE = DIR_PATH + "\\TestFile"
DIR_TO_DELETE  = DIR_PATH + "\\DirToDelete"
DIR_TO_DELETE_NOT_EMPTY  = DIR_PATH + "\\DirToDelete_NoEmpty"


def Delete_File():
    os.remove(FILE_TO_DELETE)

def Delete_File_IfExists():
    # If the file exists, delete it
    if os.path.isfile(FILE_TO_DELETE):
        os.remove(FILE_TO_DELETE)
    else:
        print(f'Error: {FILE_TO_DELETE} not a valid filename')

def Delete_File_IfExists_Exc():
    # Use exception handling
    try:
        os.remove(FILE_TO_DELETE)
    except OSError as e:
        print(f'Error: {FILE_TO_DELETE} : {e.strerror}')
        
        
def Delete_Dir():
    try:
        os.rmdir(DIR_TO_DELETE)
    except OSError as exc:
        print(f'Error: {DIR_TO_DELETE} : {exc.strerror}')  
        
def Delete_DirPath():
    trash_dir = Path(DIR_TO_DELETE)
    try:
        trash_dir.rmdir()
    except OSError as exc:
        print(f'Error: {DIR_TO_DELETE} : {exc.strerror}')  
        
        
        
        
def DeletingDirectoryTrees():
    try:
        shutil.rmtree(DIR_TO_DELETE_NOT_EMPTY)
    except OSError as e:
        print(f'Error: {DIR_TO_DELETE} : {e.strerror}')

   
def DeletingDirectoryTrees_OS():
    for dirpath, dirnames, files in os.walk(DIR_TO_DELETE_NOT_EMPTY, topdown=False):
        try:
            #print(files);
            print(dirnames);
            #os.rmdir(DIR_TO_DELETE_NOT_EMPTY)
        except OSError as exc:
            print(f'Error: {DIR_TO_DELETE} : {exc.strerror}')
            pass

###########################################
if __name__ == '__main__':
    # Delete_File();
    # Delete_File_IfExists();
    # Delete_File_IfExists_Exc();
    
    # Delete_Dir();
    # Delete_DirPath();
    
    # DeletingDirectoryTrees();
    DeletingDirectoryTrees_OS();
    
    
    
    
    
    
    
    
    