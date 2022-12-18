
from enum import Enum, unique
from test.test_telnetlib import tl

@unique
class TargetType(Enum):
    UNDEFINED = 0;
    UNIT_TESTS = 1;
    BROWSER_TESTS = 2;
    PERFORMANCE_TESTS = 3;
    INSTALLER_PY_TESTS = 4;

class Target(dict):
    
    def __init__(self, **args):
        # Validate is we have all mandatory parameters:
        mandatory = {"name", "description", "buildCommand", "executableName"};
        for param in mandatory:
            if args.get(param) is None:
                raise ValueError("Mandatory parameter '" + param + "' is missing."); 
            
        # Calling the base class constructor:
        super(Target, self).__init__(args);
    
    def __GetParameter(self, parameterName):
        return self.get(parameterName);
    
    @property
    def name(self):
        return self.__GetParameter("name");
    
    @property
    def description(self):
        return self.__GetParameter("description");
    
    @property
    def buildCommand(self):
        return self.__GetParameter("buildCommand");
    
    @property
    def executableName(self):
        return self.__GetParameter("executableName");
    
    @property
    def type(self):
        return self.__GetParameter("type");        
    
def TargetsTests():
    target = Target(name = "TestName", 
                    description = "TargetDesc", 
                    buildCommand = "build_cmd_test", 
                    executableName = "erere.exe", 
                    type = TargetType.UNIT_TESTS,
                    osSupported = {"Win7", "Win8"})

    #target.ShowInfo();

    print(target.name);
    print(target.description);
    print(target.buildCommand);
    print(target.executableName);
    print(target.type);
    
    oss = target.get("osSupported");
    if oss is not None:
        for os in oss:
            print(os);
            
            
class Integer(object):
    __value = 0;
    
    def __init__(self, value: int = 0):
        self.__value = value;
        
    def __str__(self):
        return "Integer(" + str(self.__value) + ")";
    
    def info(self):
        print (self.__value);



def dictAddDeleteTest():
    int1 = Integer(1);
    int2 = Integer(2);
    int3 = Integer(3);
    int4 = Integer(4);
    
    T = [];
    T.append(int1);
    T.append(int2);
    T.append(int3);
    
    for obj in T:
        print(obj);
        
    try :
        T.remove(int4);
    except ValueError as exc: 
        print(exc)

    
    for obj in T:
        print(obj);

if __name__ == '__main__':
    # dictAddDeleteTest();

    results = dict();
    results["type"] = "Value1";
    results["type1"] = "Value2";
    results["type2"] = "Value3";
    
    print(results);

    
    
    