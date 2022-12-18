
def CreateTest():
    unique_strings = set();
    
    unique_strings.add("Value1")
    unique_strings.add("Value2")
    unique_strings.add("Value2")
    unique_strings.add("Value3")
    unique_strings.add("Value3")
    
    print(unique_strings);
    
    
def CreateTest2():
    py_set_mix = {11, 1.1, "11", (1, 2)}
    print(py_set_mix)
    
    
def UpdateSet_Simple():
    set = {5,6,7};
    

    set.update([3,4]);
    print(set)
    
    
def UpdateSet():
    # Let's try to change a Python set
    py_set_num = set({77, 88});
    
    try:
        print(py_set_num[0])
    except Exception as ex:
        print("Error in py_set_num[0]:", ex)
    
    print("The value of py_set_num:", py_set_num)
    
    # Let's add an element to the set
    py_set_num.add(99)
    print("The value of py_set_num:", py_set_num)
    
    # Let's add multiple elements to the set
    py_set_num.update([44, 55, 66])
    print("The value of py_set_num:", py_set_num)
    
    # Let's add a list and a set as elements
    py_set_num.update([4.4, 5.5, 6.6], {2.2, 4.4, 6.6})
    print("The value of py_set_num:", py_set_num)


def Remove():
    str_set = set({"Val1","Val2","Val3","Val4","Val5","Val6"});
    
    str_set.remove("Val2");
    print(str_set);
    
    try:
        str_set.remove("Val67");
        print(str_set);
    except Exception as exc:
        print("Exception:", exc)
        
def Discard():
    str_set = set({"Val1","Val2","Val3","Val4","Val5","Val6"});
    
    str_set.discard("Val2");
    print(str_set);
    
    try:
        str_set.discard("Val67");
        print(str_set);
    except Exception as exc:
        print("Exception:", exc)
       
       
def Pop():
    # Let's use the following Python set
    numbers_set = {22, 33, 55, 77, 99}
    print("SET: ", numbers_set, "\n")
    
    # pop an element from the set
    el = numbers_set.pop()
    print("Pop-ed element: ", el, "\nSET: ", numbers_set, "\n")

    # pop an element from the set
    el = numbers_set.pop()
    print("Pop-ed element: ", el, "\nSET: ", numbers_set, "\n")
    
    
def Union():
    numbers_set_1 = {11, 22, 33, 44, 55}
    numbers_set_2 = {44, 55, 66, 77, 88}
    print("SET 1: ", numbers_set_1, ", SET 2: ", numbers_set_2)
    
    numbers_set_3 = numbers_set_1.union(numbers_set_2)
    print("SET 3: ", numbers_set_3)
    

def Intersection():
    numbers_set_1 = {11, 22, 33, 44, 55}
    numbers_set_2 = {44, 55, 66, 77, 88}
    print("SET 1: ", numbers_set_1, ", SET 2: ", numbers_set_2)
    
    numbers_set_3 = numbers_set_1.intersection(numbers_set_2)
    print("SET 3: ", numbers_set_3)


def Intersection2():
    numbers_set_1 = {11, 22, 33, 44, 55}
    numbers_set_2 = {44, 55, 66, 77, 88}
    print("SET 1: ", numbers_set_1, ", SET 2: ", numbers_set_2)
    
    numbers_set_3 = numbers_set_1 & numbers_set_2;
    print("SET 3: ", numbers_set_3)    


def Difference():
    numbers_set_1 = {1,2,3,4,5}
    numbers_set_2 = {3,4,5,6,7}
    print("SET 1: ", numbers_set_1, ", SET 2: ", numbers_set_2)
    
    numbers_set_3 = numbers_set_1.difference(numbers_set_2)
    print("SET 3: ", numbers_set_3)
    
    numbers_set_4 = numbers_set_2.difference(numbers_set_1)
    print("SET 4: ", numbers_set_4)
    
    
def Difference2():
    numbers_set_1 = {1,2,3,4,5}
    numbers_set_2 = {3,4,5,6,7}
    print("SET 1: ", numbers_set_1, ", SET 2: ", numbers_set_2)
    
    numbers_set_3 = numbers_set_1 - numbers_set_2;
    print("SET 3: ", numbers_set_3)
    
    numbers_set_4 = numbers_set_2 - numbers_set_1;
    print("SET 4: ", numbers_set_4)
    

##############################################################

if __name__ == '__main__':

    # CreateTest();
    # CreateTest2();
    
    UpdateSet_Simple();
    # UpdateSet();
     
    # Remove();
    # Discard();
    # Pop();
    # Union();
    # Intersection();
    # Intersection2();
    
    # Difference();
    # Difference2();
 
    
    
    
    
    