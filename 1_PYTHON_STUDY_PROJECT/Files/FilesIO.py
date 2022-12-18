import os
import shutil


def Write2File():
    filePath = "C:\\Temp\\4\\1.text"
    file = open(filePath, 'w')
    file.write("TEST")


def ReadFile1():
    filePath = "R:\\Temp\\FILES\\TestFile1.txt"
    file = open(filePath, 'r')
    line = file.readline()
    print(line)


def ReadFile2():
    lines = list();
    filePath = "R:\\Temp\\FILES\\hosts"
    with open(filePath) as file:
        for line_terminated in file:
            line = line_terminated.rstrip('\n')
            lines.append(line);
    for line in lines:
        print(line);


def ReadFile3():
    lines = list();
    filePath = "D:\Documents\AllTestList\TestList.txt"
    with open(filePath) as file:
        for line_terminated in file:
            line = line_terminated.rstrip('\n')
            lines.append(line);
    for line in lines:
        print(line);


''' Read and rerite file '''


def RewriteFile():
    file_path = "R:\\Temp\\FILES\\TestFile3.txt";

    lines = list();
    with open(file_path) as file:
        for line_terminated in file:
            line = line_terminated.rstrip('\n')
            lines.append(line);

    with open(file_path, 'w') as file:
        file.write("TEST");

    for line in lines:
        print(line);


""" SafeQueue clas: """


class SafeQueue(object):

    def __init__(self) -> None:
        self.list = list();
        print("__init__");

    def __del__(self):
        print("__del__");


def CountFiles(folder_path: str):
    file_list = {};
    if True == os.path.exists(folder_path) and True == os.path.isdir(folder_path):
        file_list = [file.name for file in os.scandir(folder_path) if file.is_file()]
    return len(file_list);


def MoveFile(src_file_path: str,
             dst_file_path: str) -> bool:
    if False == os.path.isfile(src_file_path) or True == os.path.isfile(dst_file_path):
        return False;
    if (dst_file_path == shutil.move(src_file_path, dst_file_path)):
        return True;
    return False;


def MoveFileTest():
    file_src = "R:\\Temp\\FILES\\DIR1\\TestFileToMove.txt";
    file_dst = "R:\\Temp\\FILES\\DIR2\\TestFileToMove.txt";
    print(MoveFile(file_src, file_dst))


if __name__ == '__main__':
    # Write2File();

    # ReadFile1();
    ReadFile2();

    # ReadFile3();

    # RewriteFile();

    # count = CountFiles("R:\\Temp\\HTML\\TEST2\\resources");
    # print(count)

    # MoveFileTest();
