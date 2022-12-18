import sys

def read_string():
    print("Enter the input.\n NOTE: To stop execution please enter 'quit'")
    # Program terminates as soon as user enters 'quit'
    for line in sys.stdin:
        if 'quit' == line.rstrip():
            break
        print(f'User Input : {line}')
    print("Terminated!")


if __name__ == '__main__':
    # read_string()

    a, b, c = input(), input(), input()
    print(a, b, c)



    pass