
from collections import defaultdict

def open_picture(profile_path):
    try:
        print(f'Opening file: {profile_path}')
        return open(profile_path, 'a+b')
    except KeyError:
        print("A KeyError occurred!")
    else:
        print("No error occurred!")
    finally:
        print("The finally statement ran!")

    try:
        print(f'Opening file: {profile_path}')
        return open(profile_path, 'a+b')
    except Exception:
        print(f'Failed to open path {profile_path}')
        # raise
    else:
        print('OK')


class Pictures(dict):
    def __missing__(self, key):
        value = open_picture(key)
        self[key] = value
        return value



if __name__ == '__main__':
    pictures = Pictures()


    handle1 = pictures['/home/andtokm/DiskS/Temp/TESTING_ROOT_DIR/pictures/out.png']
    handle2 = pictures['/home/andtokm/DiskS/Temp/TESTING_ROOT_DIR/pictures/out1.png']

    # handle.seek(0)
    # image_data = handle.read()
