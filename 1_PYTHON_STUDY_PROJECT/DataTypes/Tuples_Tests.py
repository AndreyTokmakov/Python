

def CreateTest():
    tup = tuple();
    print(tup);
    
    tup2 = ('a', 'b', );
    print(tup2);

    tup3 = tuple('hello, world!')
    print(tup3);
    
    tup4 = tuple((1,2,3,4,5,6))
    print(tup4);

    
def GetTuppleElement():
    tup = tuple(('Value1','Value2','Value3','Value4','Value5'))
    print(tup);
    
    print("tup[0:2]: ",tup[0:2])
    print("tup[1:3]: ",tup[1:3])
    print("tup[4]: ",tup[4])
    
    
def PrintPuble():
    strings = tuple(('Value1','Value2','Value3','Value4','Value5'))
    for str in strings:  
        print(str)
    
    
def Tupple2List():
    tup = tuple(('Value1','Value2','Value3','Value4','Value5'))
    print(tup);
    print(type(tup))

if __name__ == '__main__':
    # CreateTest();
    # GetTuppleElement();
    # Tupple2List();
    PrintPuble();