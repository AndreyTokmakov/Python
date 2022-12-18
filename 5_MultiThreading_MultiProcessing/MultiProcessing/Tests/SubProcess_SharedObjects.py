
import threading
from threading import Thread
from time import sleep
from multiprocessing import Process, Value, Array, Manager
from multiprocessing.managers import BaseManager

# SingletonMixin :
class SingletonMixin(object):
    __singleton_lock = threading.Lock()
    __singleton_instance = None

    @classmethod
    def instance(cls):
        if not cls.__singleton_instance:
            with cls.__singleton_lock:
                if not cls.__singleton_instance:
                    cls.__singleton_instance = cls()
        return cls.__singleton_instance
    

# Singleton :
def Singleton(cls):
    instances = {}
    def getinstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return getinstance


''' SharedClass class. '''
class SharedClass(object):
    # Default SharedClass class constructor:
    def __init__(self, *args, **kwargs):
        # Construct base object instance:
        object.__init__(self, *args, **kwargs);
        self.__text = None;
        
    @property
    def text(self):
        return self.__text;

    @text.setter
    def text(self, text: str):
        self.__text = text;
        
        # Overload toString() method: 
    def __str__(self):
        return "[\"Text\": {0}]".format(self.__text);
    
''' SimpleVariable class. '''
class SimpleVariable(object):

    # Default SimpleVariable class constructor:
    def __init__(self, name: str = "", value: int = 0, *args, **kwargs):
        print("SimpleVariable()")
        # Construct base object instance:
        object.__init__(self, *args, **kwargs);
        self.__name = name;
        self.__value = value;  
        
    @property
    def name(self):
        return self.name;

    @name.setter
    def name(self, name: str):
        self.__name = name;

    @property
    def value(self):
        return self.__value;

    @value.setter
    def value(self, value: int):
        self.__value = value;
        
    def Info(self):
        info = "SimpleVariable->TEST. [\"Name\": {0}, \"Value\": {1}]".format(self.__name, self.__value);
        print(info)
        
        # Overload toString() method: 
    def __str__(self):
        return "[\"Name\": {0}, \"Value\": {1}]".format(self.__name, self.__value);

''' SimpleVariable class. '''
@Singleton
class SimpleSingletonVariable(object):

    # Default SimpleSingletonVariable class constructor:
    def __init__(self, *args, **kwargs):
        # Construct base object instance:
        object.__init__(self, *args, **kwargs);
        self.__name = "Test";
        self.__value = 123;  
        
    @property
    def name(self):
        return self.name;

    @name.setter
    def name(self, name: str):
        self.__name = name;

    @property
    def value(self):
        return self.__value;

    @value.setter
    def value(self, value: int):
        self.__value = value;
        
        # Overload toString() method: 
    def __str__(self):
        return "[\"Name\": {0}, \"Value\": {1}]".format(self.__name, self.__value);



def SingletonTest1():
    print("SingletonTest1");
    obj = SimpleSingletonVariable();
    obj.name = "TEST12344";
    obj.value = 12345;
    print("SingletonTest1 ", str(obj))

def SingletonTest2():
    print("SingletonTest2");
    obj = SimpleSingletonVariable();
    print("SingletonTest2 ", str(obj))

################################################################################################

sub_process = None;

def Task(count:int = 10)-> bool:
    for i in range(0, count):
        print("print_mynumber: ", i)
        sleep(1)
    return True;

def Task2(obj: SimpleVariable = None)-> bool:
    obj.Info();
    obj.value = 11;
    obj.Info();
    return True;

def Task3(obj: SharedClass = None)-> bool:
    print("Task3 ", str(obj))
    obj.text = "UPDATED TEXT";
    print("Task3 ", str(obj))
    return True;

def ForceStopProcess(proc)-> bool:
    if (True == proc.is_alive()):
        proc.terminate()
        return not proc.is_alive()
    return True;

def RunProcess():
    global sub_process
    sub_process = Process(target = Task, args = ( ))
    sub_process.start()

    sub_process.join(6)
    ForceStopProcess(sub_process);
    
def RunProcess2():
    global sub_process
    obj = SimpleVariable(name = "Test", value = 10)
    print("Main: " + str(obj))
    
    sub_process = Process(target = Task2, args = (obj, ))
    sub_process.start()
    sub_process.join(6)
    
    
    print("Main: " + str(obj))
    
    
def RunProcess3():
    
    BaseManager.register('SharedClass', SharedClass)
    manager = BaseManager()
    manager.start()
    
    # obj = SharedClass()
    sharedObj = manager.SharedClass()
    print(sharedObj)

    obj = SharedClass()
    print(obj)

    
def Modify(input_dist):
    
    #var = SimpleVariable("Logger", 222);
    
    #input_dist["Logger"] = var
    
    var1 = input_dist.get("Config");
    var1.Info();
    

def RunProcess4():
    manager = Manager()
    d = manager.dict()
    
    var = SimpleVariable("Config", 111);
    d["Config"] = var
    

    p = Process(target=Modify, args=(d,))
    p.start()
    p.join()


################################################################################################

if __name__ == '__main__':
    # RunProcess()  
    RunProcess2();
    # RunProcess3();
    # RunProcess4();
    
    #SingletonTest1()
    #SingletonTest2();
    
    
    

