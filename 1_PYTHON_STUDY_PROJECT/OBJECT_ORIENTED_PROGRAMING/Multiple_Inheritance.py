'''
Created on Nov 26, 2020
@author: AndTokm
'''

# Value class 
class Value(object):
    
    def __init__(self, value = 1):
        self.__value = value
    
    def info(self):
        print(self.__value)
        
# Description class 
class Description(object):
    
    def __init__(self, description = "Some_Description"):
        self.__description = description
    
    def dscription(self):
        print(self.__description)
    
# ComplexObject class 
class ComplexObject(Value, Description):
    
    def __init__(self, value = 1, description = "Some_Description"):
        Value.__init__(self, value) 
        Description.__init__(self, description)
        
########################################################################
        
# first parent class 
class Manager(object):                   
    def __init__(self, name, idnumber): 
        self.name = name 
        self.idnumber = idnumber 
  
# second parent class       
class Employee(object):                 
    def __init__(self, salary, post): 
        self.salary = salary 
        self.post = post 
  
# inheritance from both the parent classes       
class Person(Manager, Employee):         
    def __init__(self, name, idnumber, salary, post, points): 
        self.points = points 
        Manager.__init__(self, name, idnumber) 
        Employee.__init__(self, salary, post)    
        print(self.salary) 
        
########################################################################

if __name__ == '__main__':
    obj = ComplexObject(122, "Test")
    obj.info()
    obj.dscription()