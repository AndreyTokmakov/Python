import winreg

ROOT_KEY_MAPPING = {
    "HKEY_CLASSES_ROOT" : winreg.HKEY_CLASSES_ROOT,
    "HKEY_CURRENT_USER" : winreg.HKEY_CURRENT_USER,
    "HKEY_LOCAL_MACHINE" : winreg.HKEY_LOCAL_MACHINE,
    "HKEY_USERS" : winreg.HKEY_USERS,
}

VALUE_TYPE_MAPPING = {
    "BINARY" : winreg.REG_BINARY,
    "DWORD" : winreg.REG_DWORD,
    "DWORD_LITTLE_ENDIAN": winreg.REG_DWORD_LITTLE_ENDIAN,
    "DWORD_BIG_ENDIAN" : winreg.REG_DWORD_BIG_ENDIAN,
    "QWORD" : winreg.REG_QWORD,
    "QWORD_LITTLE_ENDIAN" : winreg.REG_QWORD_LITTLE_ENDIAN,
    "EXPAND_SZ" : winreg.REG_EXPAND_SZ,
    "LINK" : winreg.REG_LINK,
    "MULTI_SZ" : winreg.REG_MULTI_SZ,
    "NONE" : winreg.REG_NONE,
    "SZ" : winreg.REG_SZ,
}

#######################################################

""" RegistryKey clas: """
class RegistryKey(object):
    # Intrernal private Registry key handle:
    __key = None;
    # Path
    __path = None;

    def __init__(self, key, path : str = None) -> None:
        print("RegistryKey.__init__()");
        self.__key = key;
        self.__path = path;

    def __del__(self):
        self.__Close();
        # We need actually make sure that internal registry key is
        # set to NULL.... but sometimes this can cause some real fuckups:
        # self.key = None;
        print("RegistryKey.__del__()");

    def __Close(self):
        if self.__key != None:
            try:
                winreg.CloseKey(self.__key);
            except WindowsError as exception:
                # TODO : Log DEBUG 
                print(exception);
                
    def __EnumKeyParams(self):
        i = 0;
        while True:
            try:
                parameter = winreg.EnumValue(self.__key, i);
                yield (parameter);
                i += 1;
            except WindowsError as exception :
                if exception.winerror == 259:
                    # This is EOL. Ok!
                    break;
                else:
                    # TODO : Log this ERROR to DEBUG 
                    print(exception);
                    break;

    def getParameter(self, paramName : str):
        try:
            pvalue, ptype = winreg.QueryValueEx(self.__key, paramName);
        except WindowsError as exception:
            # TODO : Log DEBUG 
            print(exception);
            return None;
        return RegistryParameter(self.__key, paramName, pvalue, ptype);
    
    def checkIfParamExists(self, paramName : str, paramType = None):
        for pname, pvalue, ptype in self.__EnumKeyParams():
            if paramName == pname:
                if None != paramType and ptype is paramType:
                    return True;
                if None == paramType:
                    return True;
        return False;

    @property
    def key(self):
        return self.__key;
    
    @property
    def path(self):
        return self.__path;
    
    @property
    def params(self):
        paramsList = list();
        for pname, pvalue, ptype in self.__EnumKeyParams():
            paramsList.append(RegistryParameter(self.__key, pname, pvalue, ptype))
        return paramsList;  

    def Close(self):
        self.__Close();
        self.__key = None;
        
#######################################################

""" RegistryParameter clas: """
class RegistryParameter(object):
    # Parent registry key:
    __key = None;
    # Parameter __name
    __name = None;    
    # Parameter value
    __value = None;
    # Parameter type
    __type = None;    

    def __init__(self, key: RegistryKey, 
                       name: str,
                       value: str, 
                       type: str) -> None:
        self.__key   = key;
        self.__name  = name;
        self.__value = value;
        self.__type  = type;

    # Overload toString() method: 
    def __str__(self):
        return self.__name + " = " + str(self.__value) + ", Type: " + str(self.__type);

    @property
    def key(self):
        return self.__key;
    
    @property
    def name(self):
        return self.__name;    
    
    @property
    def value(self):
        return self.__value;
    
    @property
    def type(self):
        return self.__type;
        
#######################################################

""" Converts a root registry key string into a winreg.HKEY_* constant: """
def RootKeyConstant(rootKey : str):
    if rootKey not in ROOT_KEY_MAPPING:
    #   raise KeyError("Unknown root registry key '%s'" % rootKey);
        print("Unknown root registry key '%s'" % rootKey);
    return ROOT_KEY_MAPPING.get(rootKey);

''' ReadRegistryKey: Opens registry key '''
def GetRegistryKey(rootKey : str, keyPath : str):
    root = RootKeyConstant(rootKey);
    if root is None:
        return None;
    try:
        key = winreg.OpenKey(root,  
                             keyPath,
                             0,     # Reserved integer, and must be zero.
                             winreg.KEY_READ);
        # TODO : Log DEBUG 
    except WindowsError as exception:
        # TODO : Log DEBUG 
        # print(exception);
        print ("Failed to open registry key '%s'" % (rootKey + "\\" + keyPath));
        return None;
    return RegistryKey(key, (rootKey + "\\" + keyPath));        
        
''' GetRegistryKeyParameter: Returns the opened registry key pram {VALUE, TYPE} '''     
def GetRegistryKeyParam(key : RegistryKey, paramName : str):
    try:
        pvalue, ptype = winreg.QueryValueEx(key.key, paramName);
    except WindowsError as exception:
        # TODO : Log DEBUG 
        print(exception);
        return None;
    return RegistryParameter(key, paramName, pvalue, ptype);
    
    
    
    
    
    
    
    
    
    
    
    
    
        