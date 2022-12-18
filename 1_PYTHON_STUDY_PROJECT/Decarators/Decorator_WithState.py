
class MyDecorator:
    def __init__(self, function):
        self.function = function
        self.counter = 0

    def __call__(self, *args, **kwargs):
        self.function(*args, **kwargs)
        self.counter+=1
        print(f"Called {self.counter} times")


@MyDecorator
def some_function():
    return 42


if __name__ == '__main__':
    some_function()
    some_function()
    some_function()
