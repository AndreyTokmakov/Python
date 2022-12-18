import datetime


def PrintLongString():
    str = '''dsdsdsdsd
            sdsdsdsds
            sdsdddddddddddd 333             333333333
            ____________ END'''
    print(str)


def SubStrings():
    str = "qwerty"

    print("str[0] = ", str[0])
    print("str[1:] = ", str[:2])
    print("str[:3] = ", str[:3])

    print("str[3:5] = ", str[3:5])

    print("str[0:2] = ", str[0:2])
    print("str[0:-2] = ", str[0:-2])

    print("str[2:] = ", str[2:])


def Join():
    print(", ".join({'1', '2', '3'}))


def Join2():
    colors = ['red', 'green', 'blue']

    separator_1 = " ";
    separator_2 = " , ";
    separator_3 = " - ";

    print(separator_1.join(colors))
    print(separator_2.join(colors))
    print(separator_3.join(colors))


def Join_Dict():
    trends = {
        1: 'AI',
        2: 'Machine Learning',
        3: 'Serverless',
        4: 'ARVR'
    }
    picks = '/'.join(trends.values())
    print(picks)

    keys = '/'.join(trends.keys())
    print(keys)


def Replace():
    str = "aaa bbb"
    print(str);

    str = str.replace("bbb", "ccc")
    print(str);


def Max():
    # maximum alphabetical character in "geeks"  
    string = "geeks"
    print(max(string))

    # maximum alphabetical character in "raj" 
    string = "raj"
    print(max(string))


def Isdecimal():
    s = "12345"
    print(s.isdecimal())

    # contains alphabets 
    s = "12geeks34"
    print(s.isdecimal())

    # contains numbers and spaces 
    s = "12 34"
    print(s.isdecimal())


def Splitlines():
    # Python code to illustrate splitlines() 
    string = "Welcome everyone to\rthe world of Geeks\nGeeksforGeeks"

    # No parameters has been passed 
    print(string.splitlines())

    # A specified number is passed 
    print(string.splitlines(0))

    # True has been passed  
    print(string.splitlines(True))


def Splitlines2():
    # Python code to illustrate splitlines() 
    string = "Cat\nBat\nSat\nMat\nXat\nEat"

    # No parameters has been passed 
    print(string.splitlines())

    # splitlines() in one line 
    print('India\nJapan\nUSA\nUK\nCanada\n'.splitlines())


def Splitlines_HTTP():
    string = "GET /index.htnl HTTP/1.1\r\nHost: bs.browser.mail.ru\r\nConnection: keep-alive"

    # No parameters has been passed 
    print(string.splitlines())

    # A specified number is passed 
    print(string.splitlines(0))

    # True has been passed  
    print(string.splitlines(True))


def Split():
    text = "127.0.0.101    data.browser.mail.ru";
    print(text.split(' '))


def Count():
    # initializing string  
    test_str = "GeeksforGeeks"

    # using count() to get count  
    # counting e  
    counter = test_str.count('ee')

    # printing result  
    print("Count of ee in GeeksforGeeks is : " + str(counter))


def Raw_Strings():
    common_string = 'C:\file.txt'
    raw_string = r'C:\file.txt'

    text = '''<div>
    <a href="#">content</a>
</div>'''

    print(common_string)  # C: ile.text
    print(raw_string)  # C:\file.txt
    print(text)


def Format_String():
    text = "Name: {0}  Value: {1}".format("Some_Name", 1212)
    print(text)


def F_String():  # Python3 program introducing f-string
    val = 'Geeks'
    print(f"{val}for{val} is a portal for {val}.")

    name = 'Tushar'
    age = 23
    print(f"Hello, My name is {name} and I'm {age} years old.")

    today = datetime.datetime.today()
    print(f"{today:%B %d, %Y}")


def Find_String():
    a: str = 'ABCDCDC'
    b: str = 'CDC'

    print(a.find(b))


def String_Replace_in_Loop():
    str = "qwerty"
    print(str)

    size = len(str);
    for i in range(0, size):
        str[i] = '1'

    print(str)


def Swap_Cases():
    str = "qwerTY"
    print(str)

    result = ""
    for s in str:
        if s.isupper():
            result += s.lower()
        else:
            result += s.upper()
    print(result)


def Swap_Cases_2():
    str = "qwerTY"
    print(str)
    str = str.swapcase()
    print(str)


def Capitalize():
    name: str = "alister"
    print(name, " -> ", name.capitalize())


def Capitalize_Name():
    name: str = "alister krawly"
    capitalized = " ".join([n.capitalize() for n in name.split()])

    print(capitalized)


########################################################################


if __name__ == '__main__':
    # Replace();
    # Isdecimal();

    # Join();
    # Join2();
    # Join_Dict();   

    # Max();

    # Splitlines();
    # Splitlines2();
    # Splitlines_HTTP();

    # Split();

    # Raw_Strings();
    # Format_String();
    # F_String();

    # Count();

    Find_String()

    # SubStrings();

    # Swap_Cases()
    # Swap_Cases_2()

    # Capitalize()
    # Capitalize_Name()

    # String_Replace_in_Loop();
