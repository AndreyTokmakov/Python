
from python_shell import Shell
from python_shell.util.streaming import decode_stream


def Test1():
    Shell.ls('-l')  # Equals "ls -l $HOME"

    command = Shell.whoami()  # Equals "whoami"
    print(command)  # Prints representation of command in shell

    print(command.command)  # prints "whoami"
    print(repr(command))  # Does the same as above

    print(command.return_code)  # prints "0"
    print(command.arguments)  # prints ""

    print(decode_stream(command.output)) # Prints out command's stdout
    print(decode_stream(command.errors)) # Prints out command's stderr


def Test2():
    # command = Shell.
    # print(command.return_code)
    pass


if __name__ == '__main__':
    # Test1()
    Test2()