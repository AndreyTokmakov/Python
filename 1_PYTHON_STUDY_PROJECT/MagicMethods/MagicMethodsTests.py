
class Integer(object):
    
    def __init__(self, value: str = None)-> None:
        print("Integer.__init__()")
        self.__value = value;
        
    def __new__(cls, *args, **kwargs):
        print("Integer.__new__()")
        instance = super(Integer, cls).__new__(cls)
        return instance

    # Overload toString() method:   
    def __str__(self, *args, **kwargs):
        return "{0}".format(self.__value);

    def __del__(self):
        print("Strings.__del__()")

    # Operator > reload     
    def __gt__(self, other)-> bool:
        return self.__value > other.__value;

    # Operator < reload    
    def __lt__(self, other)-> bool:
        return self.__value < other.__value;
    
    # Operator >= reload     
    def __ge__(self, other)-> bool:
        return self.__value >= other.__value;

    # Operator <= reload 
    def __le__(self, other)-> bool:
        return self.__value <= other.__value;

    # Operator != reload 
    def __ne__(self, other)-> bool:
        return self.__value != other.__value;

    # Operator == reload 
    def __eq__(self, other)-> bool:
        return self.__value == other.__value;  
    
#############################################

if __name__ == '__main__':
    int1 = Integer(111);
    int2 = Integer(111);
    
    print(int1, "  ", int2);
    print(int1 > int2);
    print(int2 > int1);
    print(int2 == int1);
    print(int2 >= int1);
    print(int2 <= int1);
    