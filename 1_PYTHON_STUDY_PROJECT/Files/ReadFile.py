
TEST_FILE_PATH = "R:\\Projects\\Python\\Python_Study_Project\\Files\\TestFile.txt";
VERSION = "S:\\Temp\\Folder_For_Testing\\VERSION";

def Read_Line():
    file = open(TEST_FILE_PATH, 'r')
    line = file.readline()
    print(line)

def Read_All_Lines():
    lines = list();
    with open(TEST_FILE_PATH) as file:
        for line_terminated in file:
            line = line_terminated.rstrip('\n')
            lines.append(line);      
    for line in lines:
        print(line);


def Read_Version_File():
    version = list();
    with open(VERSION) as file:
        for line_terminated in file:
            line = line_terminated.rstrip('\n')
            number = line.split("=")[1]
            version.append(number)
    print(".".join(version));
    
##################################################
if __name__ == '__main__':
    # Read_Line();
    # Read_All_Lines();
    
    
    Read_Version_File();