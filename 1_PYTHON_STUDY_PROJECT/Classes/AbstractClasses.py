
from abc import ABC, abstractmethod
 
''' Base class: '''
class Base(ABC):
 
    def __init__(self, value):
        self.value = value
        super().__init__()
    
    @abstractmethod
    def do_something(self):
        pass
    
    
''' Derived class: '''
class Derived(Base):

    def do_something(self):
        super().do_something()
        
        print("The enrichment from AnotherSubclass")
        print(self.value)
    

if __name__ == '__main__':
    obj = Derived("SOME_VALUE");
    obj.do_something()
    
    
    obj = Base("SOME_VALUE");
    obj.do_something()