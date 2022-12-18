
def TEST_IfNote():
    val = None;
    if not val:
        print ("val is None")
    else:
        print ("val is specified.")

def Test():
    print ("TEST");
    
    
def Replace_Test():
    words = ["test1", "test25", "test43", "test4"]
    words = [w.replace('test25', 'test2') for w in words]
    words = [w.replace('test43', 'test3') for w in words]
    
    print (words)    
    
def isNightly(status):
        result = "";
        if result is not None:
            return False;
        return result.lower() in "true";
    
def LambdaTest():
    
    values = [ "COMMIT", "NIGHTLY", " Commit12345 "];
    
    
    result = lambda str : str.strip() in values;
    print (result(" Commit12345 "));
    

if __name__ == '__main__':
    #TEST_IfNote();
    #Replace_Test();
    
    result = " true ";
    b = result.lower() in "true";
    
    print (b);