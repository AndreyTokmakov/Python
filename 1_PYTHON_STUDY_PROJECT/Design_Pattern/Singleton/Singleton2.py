'''
Created on Oct 24, 2020

@author: AndTokm
'''

class Singleton(object):
    
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Singleton, cls).__new__(cls)
        return cls.instance

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