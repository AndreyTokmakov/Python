'''
Created on Oct 24, 2020

@author: AndTokm
'''

def Formated_Print_1():
    formatter = "%r %r %r %r"
    
    print (formatter % (1, 2, 3, 4))
    print (formatter % ("one", "two", "three", "four"))
    print (formatter % (True, False, False, True))
    print (formatter % (formatter, formatter, formatter, formatter))
    print (formatter % (
        "I had this thing.",
        "That you could type up right.",
        "But it didn't sing.",
        "So I said goodnight."
    ))
    
    
def Formated_Print_2():
    formatter = "{0} {1} {2} {3}"
    
    print (formatter.format(1, 2, 3, 4))
    print (formatter.format("one", "two", "three", "four"))
    print (formatter.format(True, False, False, True))
    print (formatter.format(formatter, formatter, formatter, formatter))
    print (formatter.format("I had this thing.",
        "That you could type up right.",
        "But it didn't sing.",
        "So I said goodnight."
    ))
    
    
def Print3():
    tabby_cat = "\tI'm tabbed in."
    persian_cat = "I'm split\non a line."
    backslash_cat = "I'm \\ a \\ cat."

    fat_cat = """
        I'll do a list:
    \t* Cat food
    \t* Fishies
    \t* Catnip\n\t* Grass
    """
    
    print (tabby_cat)
    print (persian_cat)
    print (backslash_cat)
    print (fat_cat)


if __name__ == '__main__':
    # Formated_Print_1();
    # Formated_Print_2();
    Print3();
    
    
    
    
    
    
    
    