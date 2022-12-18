
fileName = "C:\\Temp\PYTHON\\TestFile.txt";

def WriteToFile_1():
    file = open(fileName, "w");
    file.write('hi there\n') ;
    file.close();

def WriteToFile_2():
    with open(fileName, "a") as file:
        file.write('file contents')

if __name__ == '__main__':
    #WriteToFile_1();
    WriteToFile_2();