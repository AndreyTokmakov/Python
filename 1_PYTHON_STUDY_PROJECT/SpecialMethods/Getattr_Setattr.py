
class AccessCounter(object):

    def __init__(self, val):
        super(AccessCounter, self).__setattr__('counter', 0)
        super(AccessCounter, self).__setattr__('value', val)

    def __setattr__(self, name, value):
        if name == 'value':
            super(AccessCounter, self).__setattr__('counter', self.counter + 1)
        super(AccessCounter, self).__setattr__(name, value)

    def __delattr__(self, name):
        if name == 'value':
            super(AccessCounter, self).__setattr__('counter', self.counter + 1)
        super(AccessCounter, self).__delattr__(name)



class TestClass1(object):
    def __getattr__(self, attrname):
        if attrname == "age":
            return 40
        else:
            raise AttributeError(attrname)

    def Info(self, text):
        print("TestClass1::Info() = ", text)
        
###########################################################


class A():   
    def Info(self):
        print("A::Info()")
        
    def Test(self, text):
        print("A::Test()", text)
        
        
class B():
        
    def __init__(self):
        self.__a = A();
        
    def Info(self):
        self.__a.Info()
        print("B::Info()")
        
    def __getattr__(self, name):
        print("B::__getattr__()", name)
        if hasattr(self.__a, name):
            def fn(*args):
                return getattr(self.__a, name)(*args)
            return fn
        else:
            raise AttributeError
    
    '''
    def Test(self, text):
        print("B::Test()", text)
    '''

def ForwartMethodCall():
    b= B();
    b.Info()
    b.Test("Some input");
    

###########################################################

def Test1():
    a = TestClass1();
    print(a.age)
    try:
        print(a.ag2e)
    except Exception as exc:
        print("ERROR: " , exc)
        
def Test_CallMethod():
    method = getattr(TestClass1(), "Info");
    method("Some_input")
    
    
    
if __name__ == '__main__':
    # Test1();
    #Test_CallMethod();
    ForwartMethodCall();
    
    
    
    
    
    
    
    