
def CreateTest():
    unique_strings = frozenset({1,2,3,4,5});
    print(unique_strings);


def CreateTest2():
    # creating a dictionary  
    Student = {"name": "Ankit", "age": 21, "sex": "Male",  "college": "MNNIT Allahabad", "address": "Allahabad"} 
      
    # making keys of dictionary as frozenset 
    key = frozenset(Student) 
      
    # printing keys details 
    print('The frozen set is:', key) 
    

def CreateTest3_Error():
    # creating a list  
    favourite_subject = ["OS", "DBMS", "Algo"] 
      
    # making it frozenset type 
    f_subject = frozenset(favourite_subject) 
      
    # below line will generate error 
    f_subject[1] = "Networking"
    

def TryUpdate():
    # Python Sample - Standard vs. Frozen Set

    # A standard set
    std_set = set(["apple", "mango","orange"])
     
    # Adding an element to normal set is fine
    std_set.add("banana")
     
    print("Standard Set:", std_set)
     
    # A frozen set
    frozen_set = frozenset(["apple", "mango","orange"])
     
    print("Frozen Set:", frozen_set)
     
    # Below code will raise an error as we are modifying a frozen set
    try:
        frozen_set.add("banana")
    except Exception as ex:
        print("Error:", ex)

##############################################################

if __name__ == '__main__':

    # CreateTest();
    # CreateTest2();
    CreateTest3_Error()
    
    # TryUpdate();
    
    
    
    
    