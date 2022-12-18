import os


def Test1():
    envs = ["HOMEDRIVE", "HOMEPATH", "TEST", "HOME", "USERNAME"];
    for key in envs:
        value = os.environ.get(key);
        print(key, "  =  ", value);
        
def getUserName():
    userName = os.environ.get('USERNAME');
    print(userName);
    
def getHomeDir():
    homedir = os.environ['HOME']
    print(homedir)

if __name__ == '__main__':
    #Test1();
    
    #getUserName();
    #getHomeDir();

    for key, value in os.environ.items():
        print ("{0} == {1}".format(key, value));