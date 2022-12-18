
import textwrap

'''
You have long strings that you want to reformat so that they fill a user-specified number of columns.
'''

text = "Look into my eyes, look into my eyes, the eyes, the eyes, \
the eyes, not around the eyes, don't look around the eyes, \
look into my eyes, you're under."

if __name__ == '__main__':
    # print(text)

    # print(textwrap.fill(text, 70))
    # print(textwrap.fill(text, 40))

    # print(textwrap.fill(text, 40, initial_indent='    '))
    
    print(textwrap.fill(text, 40, subsequent_indent='    '))