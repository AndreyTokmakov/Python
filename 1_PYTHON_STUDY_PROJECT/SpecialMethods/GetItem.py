
class Person:
    def __init__(self,name,age):
        self.name = name
        self.age = age

    def __getitem__(self,key):
        print ("Inside `__getitem__` method!")
        return getattr(self,key)
    
    
class Building(object):
    def __init__(self, floors):
        self._floors = [None]*floors
         
    def __setitem__(self, floor_number, data):
        self._floors[floor_number] = data
          
    def __getitem__(self, floor_number):
        return self._floors[floor_number]
    
    def __delitem__ (self, floor_number):
        del self._floors[floor_number];
    
class Foo:
    def __getitem__(self, key):
        print("Foo::__getitem__(): ", key)
        return None


def Test():
    p = Person("Subhayan",32)
    print (p["age"])


def Test2():
    building1 = Building(4) # Construct a building with 4 floors
    building1[0] = 'Reception'
    building1[1] = 'ABC Corp'
    building1[2] = 'DEF Inc'
    print( building1[2] )
    
def Test2_del():
    building1 = Building(4) 
    
    building1[0] = 'Reception'
    print (building1[0])
    
    del building1[0]
    print (building1[0])

def Test3():
    foo = Foo()
    foo[1] # => print(1)
    foo["aaa"] # => print("aaa")

if __name__ == '__main__':
    # Test();
    # Test2();
    # Test2_del();
    Test3();
    
    
    
    
    
    