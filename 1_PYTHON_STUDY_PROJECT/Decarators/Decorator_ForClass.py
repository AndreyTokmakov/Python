def AddCalcMethod(target):
    def calc(self):
        print('Calc() method is called!')
        return 42

    target.calc = calc
    return target


def Add_Method_To_Class():
    
    @AddCalcMethod
    class MyClass:
        def __init__(self):
            print("MyClass __init__")

    my_obj = MyClass()
    print(my_obj.calc())


if __name__ == '__main__':
    Add_Method_To_Class()
