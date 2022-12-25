
from shlex import join, quote, split
from typing import List


def join_test():
    cmds: List = ['echo', '-n', 'Multiple words']
    command: str = join(cmds)

    print(command)


def bad_cmd():
    filename = 'somefile; DELETE ALL'
    command = 'ls -l {}'.format(filename)
    print(command)  # executed by a shell: boom!


def cmd1():
    filename = 'somefile; DELETE ALL'
    command = 'ls -l {}'.format(quote(filename))
    print(command)


def split_test():
    input_command = 'SOME BAD CMD1; DELETE ALL'
    command = "ping -c 1 {}".format(input_command)
    args = split(command)
    print(args)


if __name__ == '__main__':
    # join_test()
    # bad_cmd()
    # cmd1()
    split_test()