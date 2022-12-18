
import functools # importing functools for reduce() 
import operator  # importing operator for operator functions 

def Sum_Elements():
    numbers = [ 1 , 3, 5, 6, 2, ] 
  
    # using reduce to compute sum of list 
    # using operator functions 
    print ("The sum of the list elements is : ",end="") 
    print (functools.reduce(operator.add, numbers)) 
      
    # using reduce to compute product 
    # using operator functions 
    print ("The product of list elements is : ",end="") 
    print (functools.reduce(operator.mul, numbers)) 
      
    # using reduce to concatenate string 
    print ("The concatenated product is : ",end="") 
    print (functools.reduce(operator.add,["geeks","for","geeks"])) 

if __name__ == '__main__':
    Sum_Elements()