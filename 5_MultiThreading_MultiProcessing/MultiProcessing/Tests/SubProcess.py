import sys
import subprocess
from threading import Thread
from time import sleep
import multiprocessing as mp

sub_process = None


# WatchDogThread function:
def WatchDogThread(count: int) -> None:
    # iter = 0
    while (True):
        iter += 1
        sleep(1)
        print("WD: Process status: ", sub_process.is_alive())
        if True == sub_process.is_alive():
            if iter >= count:
                print("foreverThread still running... we should stop it.")
                sub_process.kill()


def print_mynumber(count: int):
    for i in range(0, count):
        print("print_mynumber: ", i)
        sleep(1)


def Test1():
    global sub_process
    sub_process = mp.Process(target=print_mynumber, args=(10,))
    sub_process.start()

    # sleep(0.5);

    # watchDogThread = Thread(target=WatchDogThread, args = (5,));
    # watchDogThread.start()


###################################################################################

def Test2():
    command = "/path/to/executable"
    try:
        proc = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                # env = envinonment,
                                shell=False)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = str(line.rstrip())
            line = line.strip("b'")
            print(line)
            sys.stdout.flush()

    except OSError as exc:
        print("Can't run process. Error code = {0}".format(exc))
        return False

    proc.wait()
    return_code = proc.poll()
    print("Return code = {0}".format(return_code))


###################################################################################

def Test3():
    try:
        proc = subprocess.Popen(["python", "task.py"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                shell=False)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = str(line.rstrip())
            line = line.strip("b'")
            print(line)
            sys.stdout.flush()

    except OSError as exc:
        print("Can't run process. Error code = {0}".format(exc))
        return False

    proc.wait()
    return_code = proc.poll()
    print("Return code = {0}".format(return_code))


###################################################################################

if __name__ == '__main__':
    # Test1()
    # Test2()
    Test3()
