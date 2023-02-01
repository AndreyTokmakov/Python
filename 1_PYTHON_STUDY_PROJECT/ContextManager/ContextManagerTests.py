from contextlib import ContextDecorator
from contextlib import contextmanager

TEMP_FILE = '/home/andtokm/DiskS/Temp/TESTING_ROOT_DIR/test.txt'


#############

def SimpleTest():
    with open(TEMP_FILE, 'w') as file:
        file.write('hello')


class mycontext(ContextDecorator):
    def __enter__(self):
        print('Starting')
        return self

    def __exit__(self, *exc):
        print('Finishing')
        return False


def CustomContext_Test():
    with mycontext():
        print('The bit in the middle')


class FileContext(object):

    def __init__(self,
                 file_path: str) -> None:
        self.__file_name = file_path

    def __enter__(self):
        print("Opening file {0}".format(self.__file_name))

        try:
            self.__file_handle = open(self.__file_name, 'w')
        except Exception as exc:
            print(exc)
        return self.__file_handle

    def __exit__(self,
                 exc_type,
                 exc_val,
                 exc_tb) -> None:
        print("Closing file {0}".format(self.__file_name))
        self.__file_handle.close()
        if exc_val:
            raise


def CustomFileContextTest():
    with FileContext(TEMP_FILE) as file:
        file.write('hello3333311113')


class FileContext_WithExc(object):

    def __init__(self,
                 file_path: str) -> None:
        self.__file_name = file_path

    def __enter__(self):
        print("Opening file {0}".format(self.__file_name))

        try:
            my_dict = {"a": 1, "b": 2, "c": 3}
            print(my_dict["g"])
        except KeyError:
            print("A KeyError occurred!")

        try:
            self.__file_handle = open(self.__file_name, 'w')
        except Exception as exc:
            print(exc)
        return self.__file_handle

    def __exit__(self,
                 exc_type,
                 exc_val,
                 exc_tb) -> None:
        print("Closing file {0}".format(self.__file_name))
        self.__file_handle.close()
        if exc_val:
            raise


def CustomFileContext_WithExcTest():
    with FileContext_WithExc(TEMP_FILE) as file:
        file.write('hello3333311113')


#####################################################################################

if __name__ == '__main__':
    # SimpleTest();
    # CustomContext_Test();
    CustomFileContextTest()
