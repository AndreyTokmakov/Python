
def PrintList(values: list)-> None:
    print (", ".join(str(x) for x in values));
    
def List_Join():
    my_list = ["Hello", "world"]
    print("-".join(my_list))
    
    
def CrateList():
    strings = list();
    
    strings.append("val1");
    strings.append("val2");
    strings.append("val3");
    
    PrintList(strings);
    
    int_list = [5,6,7];
    print(type(int_list), " = ", int_list)

def CrateList2():
    strings = [];
    
    strings.append("val1");
    strings.append("val2");
    strings.append("val3");
    
    print(len(strings), ":", strings);
    
    strings.clear()
    
    print(len(strings), ":", strings);
    
def CreateList3():
    numbers = [ x for x in range(20) ]
    print(numbers);
    
    h = [ letter for letter in 'hello' ]
    print(h);
    
    player_list = [ 'alice','xena','bob','veronica' ]
    sub_list = [player for player in player_list if player != 'bob']
    print(sub_list);
    

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
    print("[1:] = ",  strings[1:])
    print("[3:]  = ", strings[3:])
    print("[::3] = ", strings[::3])
    print("[:-3] = ", strings[:-3])
    
    strings[1:2] = ["Val0", "Val0", "val0"];
    print(strings)
    
    # del Strings[:-2]
    # print(Strings)
    
    
def Contains():
    strings1 = ["val0","val1","val53"];
    strings2 = ["val0","val1","val2", "val3", "val4", "val5"];
    result = all(elem in strings2 for elem in strings1)
    print(result);


def Contains2():
    strings = ['update.run', 'update.successful', 'update.run', 'update.install', 'install_started', 'update', 'install_finished', 'update.successful'];
    val = ['update.successful']
    # result = all(elem in strings2 for elem in strings1)
    
    print(val[0] in strings);


def Contains_ALL():
    strings = ['one', 'two',' three', 'four', 'five', 'six', 'seven'];
    to_find = ['one', 'two',' three']

    result = all(elem in strings for elem in to_find)
    print(result);
    
    to_find.append("four1")
    
    result = all(elem in strings for elem in to_find)
    print(result);
    

def Delete_TopRecord():
    strings = ["val1","val2", "val3"];
    

    
    print("Pop: ", strings.pop(0));
    PrintList(strings);


if __name__ == '__main__':
    # Test();
    # CrateList()
    # CrateList2();
    CreateList3();
    
    # Sort_Extend_Insert();
    # Pop_Test();
    # Index_Count_Test();
    # SliceTests();
    
    # Contains();
    # Contains2();
    # Contains_ALL();
    
    
    # List_Join();
    
    # Delete_TopRecord();
    