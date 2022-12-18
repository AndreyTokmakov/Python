
class ValidationError(AssertionError):
    
    def __init__(self):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        # Now for your custom code...
        self.errors = errors

def RunTest(value: int = 0)-> None:
    if (value > 10):
        raise ValidationError("Value {0} is greater than 10".format(value))
    print("Test OK. Value: {0}".format(value))


if __name__ == '__main__':
    
    RunTest(1);
    RunTest(12);