
import os
import shutil
#from pathlib import Path

from distutils.dir_util import copy_tree, remove_tree

DIR_COPY_PATH = "S:\\Temp\\Folder_For_Testing\\COPY";
DIR_MOVE_PATH = "S:\\Temp\\Folder_For_Testing\\MOVE";

COPY_FROM_DIR = DIR_COPY_PATH + "\\From";
COPY_TO_DIR   = DIR_COPY_PATH + "\\To";

FILE_TO_COPY_SRC = COPY_FROM_DIR + "\\File_1.txt"
FILE_TO_COPY_DST = COPY_TO_DIR + "\\File_1.txt"

MOVE_FROM_DIR = DIR_MOVE_PATH + "\\From";
MOVE_TO_DIR   = DIR_MOVE_PATH + "\\To";

########################################################

def CopySingleFile():
    shutil.copy(FILE_TO_COPY_SRC, FILE_TO_COPY_DST);

def CopyingDirectories():
    shutil.copytree(COPY_FROM_DIR, COPY_TO_DIR + "\\To2");


########################################################

def MoveDir():
    shutil.move(MOVE_FROM_DIR + "\\browser", MOVE_TO_DIR)
    # shutil.move(MOVE_TO_DIR + "\\dir1_moved", MOVE_FROM_DIR + "\\dir1")

def MoveDir_CopyAndDelete():
    src = MOVE_FROM_DIR + "\\browser";
    destination = MOVE_TO_DIR + "\\browser"
    print("Copy:", src, ". To:", destination)
    shutil.copytree(src, destination);


def MoveDir_CopyAndDelete_Distutils():
    src = MOVE_FROM_DIR + "\\browser";
    destination = MOVE_TO_DIR + "\\browser"
    
    print("Copy:", src, ". To:", destination)
    copy_tree(src, destination);
    remove_tree(src)

def RenamingFile():
    os.rename(MOVE_FROM_DIR + '\\File_1.txt', MOVE_FROM_DIR + '\\File_New.txt')
    # os.rename(MOVE_FROM_DIR + '\\File_New.txt', MOVE_FROM_DIR + '\\File_1.txt')


if __name__ == '__main__':
    # CopySingleFile();
    # CopyingDirectories();
    
    # MoveDir();
    # MoveDir_CopyAndDelete();
    MoveDir_CopyAndDelete_Distutils();
    # RenamingFile();
    
    
    
    
    
    
    
    
    
    