
from __future__ import annotations
from typing import Optional
from threading import Lock, Thread

########################################################################################    

class SingletonMeta(type):
    ''' Static class instace: '''
    _instance: Optional[Singleton] = None

    def __call__(self) -> Singleton:
        if self._instance is None:
            self._instance = super().__call__()
        return self._instance
    
class SingletonMetaThreadSafe(type):
    ''' Static class instace: '''
    _instance: Optional[Singleton] = None
    ''' Lock: '''
    _lock: Lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super().__call__(*args, **kwargs)
        return cls._instance
    
    
    
class SingletonT(metaclass = SingletonMeta):
    
    value: str = None
    
    def __init__(self, value: str) -> None:
        self.value = value

    def doSomething(self):
        print("do something");
        
class SingletonM(metaclass=SingletonMetaThreadSafe):
    value: str = None

    def __init__(self, value: str) -> None:
        self.value = value

    def doSomething(self):
        print("do something");
        
        
def test_singleton(value: str) -> None:
    singleton = SingletonM(value)
    print(singleton.value)
    
def SingletonMetaTest():
    print("If you see the same value, then singleton was reused (yay!)\n"
          "If you see different values, then 2 singletons were created (booo!!)\n\n"
          "RESULT:\n")
    
    process1 = Thread(target=test_singleton, args=("FOO",))
    process2 = Thread(target=test_singleton, args=("BAR",))
    process1.start()
    process2.start()    
    
########################################################################################        

class Singleton(object):
    
    def __new__(cls):
        # Seal the class instance creation
        if not hasattr(cls, 'instance'):
            cls.instance = super(Singleton, cls).__new__(cls)
        return cls.instance
    
    def __init__(self):
        
        print("Singleton.__init__()");
        self.__counter = 0;
        
    def setCounter(self, value):
        self.__counter = value;
        
    def getCounter(self):
        return self.__counter;        
    
########################################################################################        
    
class Singleton2:
    
    __instance = None

    def __init__(self):
        self.__counter = 0;

    @staticmethod
    def getInstance():
        if Singleton2.__instance == None:
            Singleton2.__instance = Singleton2()
        return Singleton2.__instance;
    
    def setCounter(self, value):
        self.__counter = value;
        
    def getCounter(self):
        return self.__counter;
        
      
########################################################################################      
        
class OnlyOne(object):
    class __OnlyOne:
        def __init__(self):
            self.val1 = None
            self.val2 = None
            
        def __str__(self):
            return "Value : " + self.val1
        
    instance = None
    
    def __new__(cls): # __new__ always a classmethod
        if not OnlyOne.instance:
            OnlyOne.instance = OnlyOne.__OnlyOne()
        return OnlyOne.instance
    
    def __getattr__(self, name):
        return getattr(self.instance, name)
    
    def __setattr__(self, name):
        return setattr(self.instance, name) 
    
########################################################################################

class Singleton3:
    __instance = None
    
    @staticmethod 
    def getInstance():
        """ Static access method. """
        if Singleton3.__instance == None:
            Singleton3();
        return Singleton3.__instance;
    
    def __init__(self):
        """ Virtually private constructor. """
        if Singleton3.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            Singleton3.__instance = self
        
        self.__counter = 0;  
            
    def setCounter(self, value):
        self.__counter = value;
        
    def getCounter(self):
        return self.__counter;
    
########################################################################################

def SignletonTest1():
    print("Signleton1 tests:");
    
    a = Singleton()
    print (id(a));
    print (a);
    
    print(a.getCounter());
    a.setCounter(12);
    print(a.getCounter());
     
    b = Singleton()
    print (id(b));
    print (b);
    print(b.getCounter());
     
    print (a is b)
    
def SignletonTest2():

    s = Singleton2.getInstance() ## class initialized, but object not created
    print(s.getCounter());
    s.setCounter(12);
    print(s.getCounter());
    
    print("Object created", Singleton2.getInstance()) # Object gets created here
    s1 = Singleton2.getInstance() ## instance already created
    print(s1.getCounter());
    
def SignletonTest3():
    
    s1 = Singleton3.getInstance()
    print(s1)
    s1.setCounter(10);
    print(s1.getCounter())
    
    s2 = Singleton3.getInstance()
    print(s2)
    
    s3 = Singleton3.getInstance()
    print(s3)
    print(s3.getCounter())
    
def OnlyOneTest():
    x = OnlyOne()
    x.val1 = 'sausage1'
    x.val2 = 'sausage2'
    
    print(x)
    
    y = OnlyOne()
    y.val1 = 'eggs1'
    y.val2 = 'eggs2'

    print(x)
    
    z = OnlyOne()
    z.val1 = 'spam1'
    z.val2 = 'spam2'

    print(x)
    

    
#################################  MAIN  ###############################################

if __name__ == '__main__':
    #SignletonTest1();
    #SignletonTest2();
    OnlyOneTest();
    #SignletonTest3();
    #SingletonMetaTest();
    
    
