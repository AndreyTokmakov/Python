
class Object(object):
 
    staticVariable = 0;
 
    def __init__(self, name):
        """Constructor"""
        self.__name = name
        Object.staticVariable = Object.staticVariable + 1;

    def setName(self, name):
        self.__name = name
    
    def getName(self):
        return self.__name
    
    def ShowInfo(self):
        print ("Object. [name : ", self.__name, ", Static variable = ", Object.staticVariable, "]");
    
if __name__ == "__main__":
    object = Object("TEST1");
    object.ShowInfo();
    
    object = Object("TEST2");
    object.ShowInfo();
    
    object = Object("TEST3");
    object.ShowInfo();