from typing import List

'''
with open(input_path) as input_file,
     open(output_path, 'w') as output_file:
     .....
'''


class ListContext(object):

    def __init__(self) -> None:
        self.__list__: List = []

    def __enter__(self) -> List:
        print('ListContext::__enter__')
        return self.__list__

    def __exit__(self, *exc):
        print(f'  ListContext::__exit__(): {self.__list__}')
        return False


class ListAppenderContext(object):

    def __init__(self, lst: List) -> None:
        self.__list__: List = lst
        print("  ListAppenderContext created:")

    def __enter__(self) -> List:
        print('  ListAppenderContext::__enter__()')
        return self.__list__

    def __exit__(self, *exc):
        print(f'  ListAppenderContext::__exit__(): {self.__list__}')
        return False


if __name__ == '__main__':
    with ListContext() as lst, ListAppenderContext(lst) as appender:
        appender.append("1323")
        appender.append("13233")
        pass
