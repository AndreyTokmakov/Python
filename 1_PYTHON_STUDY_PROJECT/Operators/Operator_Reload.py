

class Integer(object):
    
    def __init__(self, value: int = 0)-> None:
        self.__value = value;

    @property
    def value(self)-> int:
        return self.value;

    @value.setter
    def value(self, value: int):
        self.__value = value; 

    # Overload toString() method: 
    def __str__(self):
        return "{0}".format(self.__value);
    
    # Overload (==) operator :  
    def __eq__(self, integer)-> bool:
        if self.__value == integer.__value:
            return True;
        return False;
                
    # Overload (!=) operator   
    def __ne__(self, integer)-> bool:
        if self.__value == integer.__value:
            return False;
        return True;

    # Overload (>) operator:  
    def __gt__(self, integer)-> bool:
        if self.__value > integer.__value:
            return True;
        return False;

    # Overload (<) operator:  
    def __lt__(self, integer)-> bool:
        if self.__value < integer.__value:
            return True;
        return False;
    
    # Overload (>=) operator:  
    def __ge__(self, integer)-> bool:
        if self.__value >= integer.__value:
            return True;
        return False;
    
    # Overload (<=) operator:  
    def __le__(self, integer)-> bool:
        if self.__value <= integer.__value:
            return True;
        return False;
    
    # Overload (+) operator:  
    def __add__(self, integer)-> bool:
        return Integer(self.__value + integer.__value);

    # Overload (-) operator:  
    def __sub__(self, integer)-> bool:
        return Integer(self.__value - integer.__value);
    

################################################

if __name__ == '__main__':
    integer1 = Integer(11);
    integer2 = Integer(22);
    integer3 = Integer(11);
    

    print(integer1 + integer2)
    print(integer1 - integer2)
    
    '''
    print(integer1, "  ", integer2, "  ", integer3)
    print("integer1 != integer2 = ", integer1 != integer2)
    print("integer1 == integer2 = ", integer1 == integer2)
    
    print("integer1 > integer2 = ", integer1 > integer2)
    print("integer1 < integer2 = ", integer1 < integer2)
    
    print("integer1 >= integer3 = ", integer1 >= integer3)
    print("integer1 <= integer3 = ", integer1 <= integer3)
    '''
    
    
    
    
    
    
    
    