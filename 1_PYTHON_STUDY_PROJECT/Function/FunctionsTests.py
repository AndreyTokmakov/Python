
def Test1():
    def func(*args):
        print( args);
    
    func(1, 2, 3, 'abc')


def Test2():
    def func(**kwargs):
        for key, value in kwargs.items():
            print("The value of {} = {}".format(key, value))
            
    func(a=1, b=2, c=3)
    print("------------------- TEST");
    func(arg1 = "Argument1", arg2 = "Argument2")


def Test3():
    def printScores(student, *scores):
        print("Student Name: {0}".format(student));
        for score in scores:
            print(score)
            
    printScores("Jonathan",100, 95, 88, 92, 99)     
    
    
def LambdaTests():
    print("Test1:");
    func = lambda x, y: print(x + y);
    func(1, 2)
    
    print("\nTest2:");
    (lambda x, y: print(x + y))(2, 3)
    
    print("\nTest3:");
    (lambda x, y: print(x + y))('a', 'b')
    
    print("\nTest4:");
    func = lambda *args: print( args );
    func(1, 2, 3 ,4);
    
    print("\nTest5:");
    def get_lambda(n):
        return lambda a : a * n
    l_func = get_lambda(10)
    print(l_func(5));
    
    
    
some_global_var = 0
    
def UpdateGlobalFuncTest():

    def increment_global():
        global some_global_var;
        some_global_var += 1
    
    print(some_global_var);
    increment_global();
    print(some_global_var);    


def PassParamByName():
    def FuncWithParams(text = "SOME_TEST", value = 123):
        print("Text:", text, ", Value:", value)

    FuncWithParams();
    FuncWithParams("TEXT1");
    FuncWithParams("TEXT2", 111);
    FuncWithParams(value=321, text = 'TETETETET');
    
    
def PosParams():
    def func(pos_params, *args):
        print("First param: ", pos_params, end = ". Other: ");
        for v in args:
            print(v, end=" ");
        
    func(123, 1, 2, 3, 4 ,5);
    func(123, {1,2,3});
    
    
    
def Recursive():
    def factorial(n):
        if n != 0:
            return n * factorial(n-1)
        else:
            return 1
    
    print(factorial(5))
    
    
def AssignFuncToParam():
    def printer(x): 
        print(x)

    var = printer;
    var(123)
    
    var2 = var;
    var2(321)

if __name__ == '__main__':
    # Test1();
    # Test2();
    # Test3();
    
    LambdaTests();
    # UpdateGlobalFuncTest();
    # PassParamByName();
    # PosParams();
    # Recursive();
    # AssignFuncToParam();
    
    
    
    
    
    