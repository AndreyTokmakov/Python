
import os
import tempfile

if __name__ == '__main__':
    #os.chdir("R:\\Projects\\browser\\src")
    #os.system("dir");
    
    print ("TEST")
    


    fp = tempfile.TemporaryFile();
    fp.write(b'Hello world!')
    print (fp.name);
    fp.close()
    
    '''
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as tmp:
            # do stuff with temp file
            tmp.write('stuff')
    finally:
        os.remove(path)
    '''