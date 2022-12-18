
TEST_FILE_PATH = "C:\\Projects\\Python_IDEA\\1_PYTHON_STUDY_PROJECT\\Files\\Test_File.txt";

def Write1():
    file = open(TEST_FILE_PATH, 'w')
    file.write("TEST")
    file.close()

def Append():
    file = open(TEST_FILE_PATH, 'a')
    file.write("TEST\n")
    file.close()

############################################
if __name__ == '__main__':
    # Write1();
    Append()