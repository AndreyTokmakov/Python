import re

def Espace():
    str = 'http://www.python.org';
    
    print(str)
    print(re.escape(str))
    
    
def Search():
    pattern = re.compile("d")
    print(pattern.search("dog")); 
    print(pattern.search("dog", 1)); 
    
    pattern = re.compile("est")
    print(pattern.search("Test")); 
    print(pattern.search("Test", 1)); 
    
def Search_Start():  
    result = re.search(r'Analytics', 'AV Analytics Vidhya AV')
    print (result)
    print (result.group(0))

    result = re.search('Analytics', 'AV Analytics Vidhya AV')
    print (result)
    print (result.group(0))

def Search_Tests(): 
    result = re.search(r'\d\d\D\d\d', r'Phone 123-12-12') 
    print(result[0] if result else 'Not found') 

    result = re.search(r'\d\d\D\d\d', r'Phone 1231212') 
    print(result[0] if result else 'Not found') 
    
    
def Search_Tests2(): 
    result = re.search(r'portal', 'GeeksforGeeks: A computer science portal for geeks') 
    print(result) 
    print(result.group()) 
      
    print('Start Index:', result.start()) 
    print('End Index:', result.end()) 


    result = re.search(r'portal2', 'GeeksforGeeks: A computer science portal for geeks') 
    print(result) 


def Match_StartsFrom():
    print(re.match(r'Beginningg', 'Beginningg Analytics Vidhya AV'))
    print(re.match(r'Beg', 'Beginningg Analytics Vidhya AV'))
 
    print(re.match(r'Analytics', 'Beginningg Analytics Vidhya AV'))
    
    
def Match_All(): 
    result = re.match(r'AV', 'AV Analytics Vidhya AV')
    print (result)
    print (result.start())
    print (result.end())

def Match_Complex(): 
    line = "Cats are smarter than dogs"
    matchObj = re.match( r'(.*) are (.*?) .*', line, re.M|re.I)
    
    if matchObj:
        print ("matchObj.group() : ", matchObj.group())
        print ("matchObj.group(1) : ", matchObj.group(1))
        print ("matchObj.group(2) : ", matchObj.group(2))
    else:
        print ("No match!!")


def Match_vs_Search():
    line = "Cats are smarter than dogs";

    matchObj = re.match( r'dogs', line, re.M|re.I)
    if matchObj:
        print("match --> matchObj.group() : ", matchObj.group())
    else:
        print("No match!!")
    
    searchObj = re.search( r'dogs', line, re.M|re.I)
    if searchObj:
        print("search --> searchObj.group() : ", searchObj.group())
    else:
        print("Nothing found!!")



def Compile(): 
    pattern = re.compile('AV')
    result = pattern.findall('AV Analytics Vidhya AV')
    print (result)
    result2 = pattern.findall('AV is largest analytics community of India')
    print (result)


def FindAll():
    print(re.findall(r'[Gg]eeks', 'GeeksforGeeks: A computer science portal for geeks'))
    print(re.findall(r'[Gg]eeks', 'GeeksforGeeks: A computer science portal for geeks'))

def FindAll_All_Symbols(): 
    result = re.findall(r'.', 'AV is largest Analytics community of India')
    print(result)

def FindAll_All_Symbols_SkipSpaces(): 
    result = re.findall(r'\w', 'AV is largest Analytics community of India')
    print(result)
    
def FindAll_AllWords_InString(): 
    result = re.findall(r'\w*', 'AV is largest Analytics community of India')
    print(result) 
    
def FindAll_AllWords_InString_SkipSpaces(): 
    result = re.findall(r'\w+', 'AV is largest Analytics community of India')
    print(result) 

def FindAll_FirstWord(): 
    result = re.findall(r'^\w+', 'AV is largest Analytics community of India')
    print(result) 

def FindAll_Last_Word(): 
    result = re.findall(r'\w+$', 'AV is largest Analytics community of India')
    print(result) 




def Find_FirstTwoSymols_ForEachWord(): 
    result = re.findall(r'\w\w', 'AV is largest Analytics community of India')
    print(result) 

def Find_LastTwoSymols_ForEachWord(): 
    result = re.findall(r'\b\w.', 'AV is largest Analytics community of India')
    print(result) 

def Find_Get_WebDomens_List(): 
    result = re.findall(r'@\w+', 'abc.test@gmail.com, xyz@test.in, test.first@analyticsvidhya.com, first.test@rest.biz')
    print(result) 

    result = re.findall(r'@\w+.\w+', 'abc.test@gmail.com, xyz@test.in, test.first@analyticsvidhya.com, first.test@rest.biz')
    print(result) 

    result = re.findall(r'@\w+.(\w+)', 'abc.test@gmail.com, xyz@test.in, test.first@analyticsvidhya.com, first.test@rest.biz')
    print(result) 


if __name__ == '__main__':
    #Espace();
    
    # Search();
    # Search_Start();
    # Search_Tests();
    # Search_Tests2();
    
    # Match_StartsFrom();
    # Match_All();
    # Match_Complex();
    # Match_vs_Search();
    
    # Compile();
    
    FindAll();
    # FindAll_All_Symbols();
    # FindAll_All_Symbols_SkipSpaces();
    # FindAll_AllWords_InString();
    # FindAll_AllWords_InString_SkipSpaces();
    # FindAll_FirstWord();
    # FindAll_Last_Word();
    
    # Find_FirstTwoSymols_ForEachWord();
    # Find_LastTwoSymols_ForEachWord();
    
    # Find_Get_WebDomens_List();
    