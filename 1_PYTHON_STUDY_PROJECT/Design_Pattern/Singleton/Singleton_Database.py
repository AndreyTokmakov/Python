'''
Created on Oct 24, 2020

@author: AndTokm
'''

class MetaSingleton(type):
    """
    There are many ways to implement the Singleton class in Python. 
    Possible way include base class, decorator, metaclass. We will use
    metaclass as it is best suited for this purpose.
    """
    _instances = {}
    
    """
    This implementation does not take into account possible changes in the 
    transmitted arguments to `__init__`.
    """
    def __call__(cls, *args, **kwargs):
        print("_instances: ", cls._instances)
        if cls not in cls._instances:
            cls._instances[cls] = super(MetaSingleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
    
    
class Database(metaclass = MetaSingleton):
    connection = None
    
    def connect(self):
        # Real connection code:
        '''
        if self.connection is None:
            self.connection = sqlite3.connect("db.sqlite3")
            self.cursorobj = self.connection.cursor()
        return self.cursorobj
        '''
        
        if (None == self.connection):
            self.connection = 1;
            print("Connected")
        else: 
            print("Already connected")
    
    
    

if __name__ == '__main__':
    db1 = Database().connect()
    db2 = Database().connect()
    print ("Database Objects DB1", db1)
    print ("Database Objects DB2", db2)