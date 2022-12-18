'''
Created on Oct 24, 2020

@author: AndTokm
'''

class SingletonMeta(type):
    """
    There are many ways to implement the Singleton class in Python. 
    Possible ways include base class, decorator, metaclass. We will use
    metaclass as it is best suited for this purpose.
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        This implementation does not take into account possible changes in 
        the transmitted arguments to `__init__`.
        """
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class Singleton(metaclass = SingletonMeta):
    
    def some_business_logic(self):
        """
        Finally, any loner should contain some business logic,
        which can be executed on its instance.
        """
        print("some_business_logic")



if __name__ == '__main__':
    s1 = Singleton()
    s2 = Singleton()

    if id(s1) == id(s2):
        print("Singleton works, both variables contain the same instance.")
    else:
        print("Singleton failed, variables contain different instances.")
        
    s1.some_business_logic();