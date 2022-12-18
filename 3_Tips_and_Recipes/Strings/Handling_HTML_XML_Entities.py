
'''
You want to replace HTML or XML entities such as &entity; or &#code; with their
corresponding text. Alternatively, you need to produce text, but escape certain characters (e.g., < , > , or & ).
'''

import html

s = 'Elements are written as "<tag>text</tag>".'

if __name__ == '__main__':
    print(s)
    print(html.escape(s))
    print(html.escape(s, quote=False))