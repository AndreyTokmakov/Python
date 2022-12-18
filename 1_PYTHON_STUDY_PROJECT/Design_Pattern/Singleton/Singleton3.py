'''
Created on Oct 24, 2020

@author: AndTokm
'''

class Singleton(object):
    # Singleton instance:
    __instance = None
    
    def __init__(self):
        if not Singleton.__instance:
            print(" __init__ method called..")
        else:
            print("Instance already created:", self.getInstance())
            
    @classmethod
    def getInstance(cls):
        if not cls.__instance:
            cls.__instance = Singleton()
        return cls.__instance
    
    # Singleton instance:
    def some_business_logic(self):
        """
        Finally, any loner should contain some business logic,
        which can be executed on its instance.
        """
        print("Singleton3 tests")


if __name__ == '__main__':
    s1 = Singleton()
    s2 = Singleton()

    if id(s1) == id(s2):
        print("Singleton works, both variables contain the same instance.")
    else:
        print("Singleton failed, variables contain different instances.")
        
    s1.some_business_logic();