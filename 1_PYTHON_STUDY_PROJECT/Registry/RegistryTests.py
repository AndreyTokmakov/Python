import os
import winreg
import os.path
from RegFuncs import GetRegistryKey;
from RegFuncs import GetRegistryKeyParam;


def CheckFileExists(filename):
    isFileExist = os.path.isfile(filename);
    print(isFileExist);

def DeleteFileIfExist(filename):
    if os.path.exists(filename):
        os.remove(filename);

def FilesTests():
    filePath = "C:\\Temp\\FILES\\TestFile.txt";
    CheckFileExists(filePath);
    DeleteFileIfExist(filePath);

def EnumKeyParams(key):
    i = 0;
    while True:
        try:
            subkey = winreg.EnumValue(key, i);
            yield subkey;
            i += 1;
        except WindowsError:
            break;


##################################


########################################################################

def Test():
    #regKey = GetRegistryKey("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mail.Ru Atom");
    regKey = GetRegistryKey("HKEY_CURRENT_USER", "Software\\Atom");
    if regKey is None:
        return;
    
    
    print(regKey.checkIfParamExists("pv", winreg.REG_SZ));
    print(regKey.checkIfParamExists("InstallerError"));
    
    
    
    '''
    params = regKey.params;
    for p in params:
        print(p);
   
'''
   
    #param = GetRegistryKeyParam(regKey, "pv4");
    #print(param)
    
    #print(regKey.path);
    #print(winreg.QueryValueEx(regKey.key, "Version"));
    #print(winreg.QueryValueEx(regKey.key, "UninstallString"));

def Test1():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mail.Ru Atom", 0, winreg.KEY_READ);

    keyInfo = winreg.QueryInfoKey(key);
    print("Info : ");
    print("    Number of sub keys : ", keyInfo[0]);
    print("    Number of values this key has : ", keyInfo[1]);
    print("");

    for param in EnumKeyParams(key):
        print(param[0], "  ", param[1], "   ", param[2]);

    version = winreg.QueryValueEx(key, "Version");
    print(version);

    uninstallString = winreg.QueryValueEx(key, "UninstallString");
    print(uninstallString);

    winreg.CloseKey(key);

########################################################################
if __name__ == '__main__':

    Test();
    #Test1();