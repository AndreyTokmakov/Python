
import json;
from enum import Enum, unique

#############  TargetType  #############

class TargetType(Enum):
    UNDEFINED = 0;
    UNIT_TESTS = 1;
    BROWSER_TESTS = 2;
    PERFORMANCE_TESTS = 3;
    INSTALLER_PY_TESTS = 4;
    
#############  Target  #############    

''' Target class : '''
class Target(dict):
    
    '''
    def __init__(self, **args):
        # Validate is we have all mandatory parameters:
        mandatory = {"name", "description", "buildCommand", "executableName"};
        for param in mandatory:
            if args.get(param) is None:
                raise ValueError("Mandatory parameter '" + param + "' is missing."); 
            
        # Calling the base class constructor:
        super(Target, self).__init__(args);
    '''        
    
    def Validate(self):
        # Validate is we have all mandatory parameters:
        mandatory = {"name", "description", "buildCommand", "executableName"};
        for param in mandatory:
            if self.get(param) is None:
                raise ValueError("Mandatory parameter '" + param + "' is missing."); 
    
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
    
#############  Target  #############    

''' TestTargets class : '''
class TestTargets(list):

    def Initialyze(self):
        jsonFile = "R:\\Projects\\Python\\PythonStudyApplication\\JsonParsing\\Targers.json";
        self.__parseJson(jsonFile)
        
    def __parseJson(self, jsonFile):
        with open(jsonFile) as jsonData:
            targetsJson = json.loads(jsonData.read());
            for targetStr in targetsJson:
                target = Target();
                for key, value in targetStr.items():
                    target[key] = value;
                self.addTarget(target); 
        
    def append(self, target):
        target.Validate();
        super(TestTargets, self).append(target);
        
    def addTarget(self, target):
        target.Validate();
        super(TestTargets, self).append(target);        
        
    def FilterByOS(self, targetOS):
        result = TestTargets();
        for target in self:
            osSupported = target.get("osSupported");
            if osSupported is None:
                result.addTarget(target);
                continue;
            for os in osSupported:
                if targetOS in os:
                    result.addTarget(target);
        return result;
    
    def FilterByType(self, type):
        result = TestTargets();
        for target in self:
            targetType = target.type;
            if targetType is None:
                result.addTarget(target);
                continue;
            if type is targetType:
                result.addTarget(target);
        return result;        
        
    def PrintList(self):
        for T in self:
            print(T);

#################################### 




if __name__ == "__main__":
    
    targets = TestTargets();
    targets.Initialyze();
    targets.FilterByOS("Win7").PrintList();
   

    
    