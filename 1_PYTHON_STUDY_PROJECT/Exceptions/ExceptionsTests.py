
def Test1():
    my_dict = {"a":1, "b":2, "c":3}
     
    try:
        value = my_dict["d"]
    except IndexError:
        print("This index does not exist!")
    except KeyError:
        print("This key is not in the dictionary!")
    except:
        print("Some other error occurred!")
        

def Test_Finaly():
    my_dict = {"a":1, "b":2, "c":3}
    try:
        value = my_dict["a"]
    except KeyError:
        print("A KeyError occurred!")
    else:
        print("No error occurred!")
    finally:
        print("The finally statement ran!")
        
        
def ReRaiseException():
    def foo():
        try:
            raise Exception("SOME_TEST_EXC");
        except Exception as exc:
            print("Exception caught 1: ", exc);
            raise;
    try:
        foo();
    except Exception as exc:
        print("Exception caught 2: ", exc);
    finally:
        print("The finally statement ran!")

#########################################
if __name__ == '__main__':
    # Test1();
    # Test_Finaly();
    ReRaiseException();