from typing import List


def Create_Simple_Lambda():
    multiply = lambda x ,y: x * y
    result = multiply(21, 2)
    print(result)


def Lambda_No_Args():
    f = lambda: True
    result = f()
    print(result)


def Filter_List():
    values: List[int] = list(range(10))
    print(f"Values: {values}")

    print(list(filter(lambda x: x % 3 == 0, values)))
    # [18, 9, 24, 12, 27]
    
    print(list(map(lambda x: x * 2 + 10, values)))
    # [14, 46, 28, 54, 44, 58, 26, 34, 64]

    squares = list(map(lambda x: x ** 2, values))
    print(f'squares: {squares}')
    
    
def Create_New_List_OldStyle():
    def miles_to_kilometers(num_miles):
        """ Converts miles to the kilometers """
        return num_miles * 1.6
 
    mile_distances = [1.0, 6.5, 17.4, 2.4, 9]
    kilometer_distances = list(map(miles_to_kilometers, mile_distances))
    print (kilometer_distances) # [1.6, 10.4, 27.84, 3.84, 14.4]
         
    
def Create_New_List():
    mile_distances = [1.0, 6.5, 17.4, 2.4, 9]
    kilometer_distances = list(map(lambda x: x * 1.6, mile_distances))
    print (kilometer_distances)
     

if __name__ == '__main__':
    Filter_List()
    
    # Create_Simple_Lambda()
    # Lambda_No_Args()
    
    # Create_New_List_OldStyle()
    # Create_New_List()
