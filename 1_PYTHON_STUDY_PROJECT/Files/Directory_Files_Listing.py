import os
import fnmatch
from pathlib import Path

DIR_PATH = "S:\\Temp\\Folder_For_Testing";


def ListDir():
    entries = os.listdir(DIR_PATH)
    for entry in entries:
        print(entry);


def ListDir_OnlyFiles():
    for entry in os.listdir(DIR_PATH):
        if os.path.isfile(os.path.join(DIR_PATH, entry)):
            print(entry)


def ListDir_SubDirs():
    for entry in os.listdir(DIR_PATH):
        if os.path.isdir(os.path.join(DIR_PATH, entry)):
            print(entry)


def ListDir_Scandir():
    entries = os.scandir(DIR_PATH)
    for entry in entries:
        print(entry, ": ", entry.name);


def ListDir_Scandir_OnlyFiles():
    with os.scandir(DIR_PATH) as entries:
        for entry in entries:
            if entry.is_file():
                print(entry.name)


def ListDir_Scandir_SubDirs():
    with os.scandir(DIR_PATH) as entries:
        for entry in entries:
            if entry.is_dir():
                print(entry.name)


def ListDir_Path():
    entries = Path(DIR_PATH)
    for entry in entries.iterdir():
        print(entry.name)


def ListDir_Path_OnlyFiles():
    files_in_basepath = (entry for entry in Path(DIR_PATH).iterdir() if entry.is_file())
    for item in files_in_basepath:
        print(item.name)


def ListDir_Path_SubDirs():
    for entry in Path(DIR_PATH).iterdir():
        if entry.is_dir():
            print(entry.name)


def ListDir_Files_Pattern():
    for entry in os.listdir(DIR_PATH):
        if entry.endswith('.txt'):  # or 'startswith'
            print(entry)


def ListDir_Files_Pattern_Ex():
    for file_name in os.listdir(DIR_PATH):
        if fnmatch.fnmatch(file_name, '*1.txt'):
            print(file_name)


def ListDir_Files_Walk():
    for dirpath, dirnames, files in os.walk(DIR_PATH, topdown=False):
        try:
            print("files: ", files);
            print("dirpath: ", dirpath);
            print("dirnames: ", dirnames);
        except OSError as exc:
            print(f'Error: {DIR_PATH} : {exc.strerror}')
            pass


def ListDir_Files_Walk2():
    for dirpath, _, files in os.walk(DIR_PATH):
        for item in files:
            fileNamePath = str(os.path.join(dirpath, item))
            print(fileNamePath);


def ListDir_Files_Walk_Cromium_Filter():
    filter = ['data', 'test'];
    for dirpath, _, files in os.walk(DIR_PATH):
        if (True == any(elem in dirpath for elem in filter)):
            for item in files:
                fileNamePath = str(os.path.join(dirpath, item))
                print(fileNamePath);


def ListDirs_Only_Walk_Cromium_Filter():
    filter = ['data', 'test'];
    for dirpath, _, files in os.walk(DIR_PATH):
        if (True == any(elem in dirpath for elem in filter)):
            print(dirpath);

        #####################################################


if __name__ == '__main__':
    # ListDir();
    # ListDir_OnlyFiles();
    # ListDir_SubDirs();

    # ListDir_Scandir();
    # ListDir_Scandir_OnlyFiles();
    # ListDir_Scandir_SubDirs();

    # ListDir_Path();
    # ListDir_Path_OnlyFiles();
    # ListDir_Path_SubDirs();

    # ListDir_Files_Pattern();
    # ListDir_Files_Pattern_Ex();

    # ListDir_Files_Walk();
    # ListDir_Files_Walk2();
    # ListDir_Files_Walk_Cromium_Filter();
    # ListDirs_Only_Walk_Cromium_Filter();
    pass
