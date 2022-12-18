
# Python program to demonstrate  
# use of class method and static method. 
from datetime import date 
  
class Person: 
    def __init__(self, name, age): 
        self.name = name 
        self.age = age 
      
    # a class method to create a Person object by birth year. 
    @classmethod
    def fromBirthYear(cls, name, year): 
        print("Classmethod for class '", cls.__name__, "'")
        return cls(name, date.today().year - year) 
      
    # a static method to check if a Person is adult or not. 
    @staticmethod
    def isAdult(age): 
        return age > 18
    
    def __str__(self):
        return ("Name: {0}, Age: {1}").format(self.name, self.age);
    
if __name__ == '__main__':
    person1 = Person('Mary', 21) 
    person2 = Person.fromBirthYear('John', 1996) 
      
    print (person1) 
    print (person2) 
    print (Person.isAdult(22)) 