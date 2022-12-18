

class TestClass(object):
    
    def __init__(self, value : str = ""):
        self.__value = value;
        
    def info(self):
        print(self.__value);
        
    def setValue(self, value : str):
        self.__value = value;
        

if __name__ == '__main__':
    
    #test = TestClass("TestCLassInitValue");
    #test.info();
    
    testObj = eval("TestClass")("ETETETE");
    testObj.info();