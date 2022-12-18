
def singleton(cls):
    instances = {}
    def getinstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return getinstance

@singleton
class MyClass:

    def setValue(self, v):
        self.__value = v;
        
    def printValue(self):
        print("Value = ", self.__value)
    
if __name__ == '__main__':
    obj1 = MyClass();
    obj1.setValue(15)
    obj1.printValue()
    
    obj2 = MyClass();
    obj2.printValue()
    