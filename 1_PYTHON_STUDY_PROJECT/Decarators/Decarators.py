'''
Created on May 31, 2020
@author: AndTokm
'''


def html_document(func):
    def wrapped():
        return "<html>" + func() + "</html>"

    return wrapped


def html_body(func):
    def wrapped():
        return "<body>" + func() + "</body>"

    return wrapped


def makebold(func):
    def wrapped():
        return "<b>" + func() + "</b>"

    return wrapped


def makeitalic(func):
    def wrapped():
        return "<i>" + func() + "</i>"

    return wrapped


@html_document
@html_body
@makebold
@makeitalic
def hello():
    return ("Hello")


#################################################################################

def some_custom_decorator(func):
    def inner1(*args, **kwargs):
        print("before Execution")

        # getting the returned value 
        returned_value = func(*args, **kwargs)
        print("after Execution")

        # returning the value to the original frame 
        return returned_value

    return inner1


# adding decorator to the function 
@some_custom_decorator
def sum_two_numbers(a, b):
    print("Inside the sum_two_numbers() function")
    return a + b


# adding decorator to the function 
@some_custom_decorator
def sum_three_numbers(a, b, c):
    print("Inside the sum_three_numbers() function")
    return a + b + c


def Decorator_With_Params():
    result = sum_two_numbers(1, 2)
    print(result)

    result = sum_three_numbers(1, 2, 3)
    print(result)


#################################################################################

# Adds a welcome message to the string 
def messageWithWelcome(str):
    # Nested function 
    def addWelcome():
        return "Welcome to "

    # Return concatenation of addWelcome() and str. 
    return addWelcome() + str


def decorate_message(function):
    print("Decorating function '" + function.__name__ + "'");

    # Nested function 
    def addWelcome(site_name):
        return "Welcome again to " + function(site_name)

        # Decorator returns a function

    return addWelcome


@decorate_message
def handle_name(site_name):
    return site_name


def Append_Result_Text():
    text = messageWithWelcome("GeeksforGeeks")
    print(text)


def Append_Result_Text2():
    text = handle_name("GeeksforGeeks")
    print(text)


#################################################################################

def a_decorator_passing_arbitrary_arguments(function_to_decorate):
    print("Decorating function '" + function_to_decorate.__name__ + "'");

    # This "wrapper" accepts any arguments
    def a_wrapper_accepting_arbitrary_arguments(*args, **kwargs):
        print("Is there any input params:")
        print(args)
        print(kwargs)
        function_to_decorate(*args, **kwargs)

    return a_wrapper_accepting_arbitrary_arguments


@a_decorator_passing_arbitrary_arguments
def function_with_no_argument():
    pass


def Function_With_no_Argument():
    function_with_no_argument();


#################################################################################

if __name__ == '__main__':
    # text = hello();
    # print (text)

    Decorator_With_Params();

    # Append_Result_Text()
    # Append_Result_Text2()

    # Function_With_no_Argument()
