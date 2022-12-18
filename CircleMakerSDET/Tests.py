import os
import subprocess
import sys

from subprocess import call
from circlemaker import draw_image
from CircleWrapper import ShapeWrapper

FILE_PATH = '/home/andtokm/DiskS/ProjectsUbuntu/Python/CircleMakerSDET/test.png'


def remove_silent(filePath: str) -> bool:
    try:
        os.remove(filePath)
        return True
    except Exception as exc:
        return False


def Test(diameter, hue):
    draw_image(diameter, hue, FILE_PATH)
    wrapper = ShapeWrapper(FILE_PATH)
    remove_silent(FILE_PATH)
    print(wrapper.getDiameter())


def call_module(diam: int, hue: int, path: str):
    try:
        proc = subprocess.Popen(["python", "circlemaker.py", "-d", str(diam), "-hue", str(hue), "-path", path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                shell=False)
    except Exception as exc:
        raise exc

    proc.wait()
    return proc.poll()


'''
class FileContext(object):

    def __init__(self,
                 diam: int, hue: int, path: str) -> None:
        self.result = 


    def __exit__(self,
                 exc_type,
                 exc_val,
                 exc_tb) -> None:
        print(f"__exit__ {self.result}")

    def __call_module(diam: int, hue: int, path: str):
        try:
            proc = subprocess.Popen(["python", "circlemaker.py", "-d", str(diam), "-hue", str(hue), "-path", path],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    shell=False)
        except Exception as exc:
            # print(f'Failed to execute command: {exc})')
            raise exc

        proc.wait()
        return proc.poll()
'''

if __name__ == '__main__':
    # Test(21, 64)

    # code = call_module(333, 64, FILE_PATH)
    # print(code)
    # remove_silent(FILE_PATH)

    print(os.path.exists(FILE_PATH))
