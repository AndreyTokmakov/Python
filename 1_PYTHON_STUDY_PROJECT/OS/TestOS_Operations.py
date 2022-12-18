import os
import os.path
# import pefile
import os.path


def CheckFileExists(filename):
    isFileExist = os.path.isfile(filename);
    print(isFileExist);


def DeleteFileIfExist(filename):
    if os.path.exists(filename):
        os.remove(filename);


def getHomeDirectory():
    homedir = os.path.expanduser("~")
    print(homedir)


if __name__ == '__main__':
    # os.chdir("R:\\Projects\\browser\\src")
    # os.system("dir");

    '''
    file_path = "R:\\Projects\\browser\\src\\out\\Debug\\mini_installer.exe";
    language_and_codepage_pairs = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')  
    print (language_and_codepage_pairs)
    
    product_name_entry = ('\\StringFileInfo\\%04x%04x\\ProductName' % language_and_codepage_pairs[0])
    print (product_name_entry)
    '''

    # src_path = "R:\\Projects\\browser\\src\\out\\Release\\chrome_child.dll";
    # pe = pefile.PE(src_path);

    '''
    filePath = "R:\\Projects\\browser\\src\\out\\Debug\\chromedriver.exe";
    CheckFileExists(filePath);
    DeleteFileIfExist(filePath);
    '''

    getHomeDirectory();
