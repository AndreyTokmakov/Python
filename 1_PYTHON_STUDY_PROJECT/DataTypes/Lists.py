import string


def PrintList(values: list)-> None:
    print (", ".join(str(x) for x in values));
    
def CrateList():
    strings = list();
    
    strings.append("val1");
    strings.append("val2");
    strings.append("val3");
    
    PrintList(strings);

def SortList():
    ints = [1, 9, 22, 2, 3, 5, 7, 4]
    PrintList(ints);
        
    ints.sort()
    PrintList(ints);

def Sort_Extend_Insert():
    strings = list();
    
    strings.append("val1");
    strings.append("val2");
    strings.append("val3");
    
    PrintList(strings);
    
    strings.extend(["val4", "val5"])
    PrintList(strings);
    
    strings.insert(2, "val3_Updater")
    PrintList(strings);
    
def Pop_Test():
    strings = ["val1","val2", "val3"];
    print("Pop: ", strings.pop());
    PrintList(strings);
    
def Index_Count_Test():
    strings = ["val1","val2", "val3", "val4", "val5"];
    PrintList(strings);
    
    print("Index of 'val3' is " , strings.index("val3", 0, 4));
    strings.remove('val3')
    
    PrintList(strings);

def SliceTests():
    strings = ["val0","val1","val2", "val3", "val4", "val5"];
    PrintList(strings);
    
    print("[1:3] = ", strings[1:3])
    print("[:3]  = ", strings[:3])
    print("[3:]  = ", strings[3:])
    print("[::3] = ", strings[::3])
    print("[:-3] = ", strings[:-3])
    
    strings[1:2] = ["Val0", "Val0", "val0"];
    print(strings)
    
    # del Strings[:-2]
    # print(Strings)

if __name__ == '__main__':
    # Test();
    # CrateList()
    # Sort_Extend_Insert();
    # Pop_Test();
    # Index_Count_Test();
    SliceTests();
    
    
    