import functools
import operator 

def FilterList():
    foo = [2 ,18, 9 , 22, 17, 24, 8, 12, 27]
    a = list(filter(lambda x: x % 3 == 0, foo))
    print(a)
    
    b = list(filter(lambda x: x % 2 == 0, foo))
    print(b)
    print()
    
    a = map(lambda x: x*2, a)
    print(list(a))
    
    
def FilterList_Generators():
    foo = [2 ,18, 9 , 22, 17, 24, 8, 12, 27]
    a = [i for i in foo if 0 == i % 3]
    print(a)
    
    b = [i for i in foo if 0 == i % 2]
    print(b)
    print()
    
    a = map(lambda x: x*2, a)
    print(list(a))

def FilterMap():
    dict_a = [{'name': 'python', 'points': 10}, {'name': 'java', 'points': 8}]
    print("original:", dict_a);
    
    print(list(map(lambda x : x['name'], dict_a))) 
    print(list(map(lambda x : x['points']*10,  dict_a)))
    print(list(map(lambda x : x['name'] == "python", dict_a))) 
   

def FilterMap_Reduce():
    sum = functools.reduce(lambda a, x: a + x, [0, 1, 2, 3, 4])
    print(sum);


def FilterMap_Reduce_MinMax():
    numbers = [1, 3, 5, 6, 2, ] 
      
    # using reduce to compute sum of list 
    print ("The sum of the list elements is : ", end = "") 
    print (functools.reduce(lambda a,b : a + b,numbers)) 
    
    # using reduce to compute maximum element from list 
    print ("The maximum element of the list is : ",end="") 
    print (functools.reduce(lambda a,b : a if a > b else b, numbers)) 
    
    
def FilterMap_Reduce_Operator():  
    # initializing list 
    lis = [1,3,5,6,2,] 
      
    # using reduce to compute sum of list using operator functions 
    print ("The sum of the list elements is : ", end = "") 
    print (functools.reduce(operator.add,lis)) 
      
    # using reduce to compute product using operator functions 
    print ("The product of list elements is : ", end = "") 
    print (functools.reduce(operator.mul,lis)) 
      
    # using reduce to concatenate string 
    print ("The concatenated product is : ", end = "") 
    print (functools.reduce(operator.add,["geeks", "for", "geeks"])) 



if __name__ == '__main__':
    # FilterList();
    FilterList_Generators();
    
    # FilterMap();
    
    # FilterMap_Reduce();
    # FilterMap_Reduce_MinMax();
    # FilterMap_Reduce_Operator();
    
