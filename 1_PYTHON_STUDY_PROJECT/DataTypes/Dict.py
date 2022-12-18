
def CreateDictTests():
    d1 = {'key1': 1, 'key2': 2}
    print(d1)

    d2 = dict(short='dict', long='dictionary')
    print(d2)
    
    d3 = dict([(1, 1), (2, 4)])
    print(d3)
    
    d4 = dict.fromkeys(['a', 'b'])
    print(d4)
    
    d5 = dict.fromkeys(['a', 'b'], 100)
    print(d5)
    
    d6 = {a: a ** 2 for a in range(7)}
    print(d6)

def Iterate_Dict():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    for key in values:
        print(key, " = ", values[key])
        
    print("\n----------------------------------");
    for key, value in values.items():
        print(key, " = ", value)
        
    print("\n----------------------------------Keys:");
    for key in values.keys():
        print(key)
        
def Pop():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    print(values);
   
    print("POP: ", "key1 = ", values.pop('key1'))
    print(values);
    
def CkeckIFKeyExists():
    values = {'key1': 1, 'key2': 2, 'key3': 3, 'key4': 4, 'key5': 5}
    print(values);
   
    print("key1 exits: ", "key1" in values);

if __name__ == '__main__':
    # CreateDictTests();
    # Iterate_Dict()
    # pop();
    CkeckIFKeyExists();
    
    
    
    
    