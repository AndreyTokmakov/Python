import random;
from threading import Thread
from time import sleep


def runSimpleThread():
    # Handler function:
    def SimpleThread():
        while True:
            sleep(1)
            print("Running");

    # Starting thread:
    thread = Thread(target=SimpleThread)
    thread.start()


def parametrizedThread():
    # Handler function:
    def threadHandler(name: str, value: int):
        print("Running thread with parameters.");
        while True:
            sleep(1)
            print("name: {0}, value: {1}".format(name, value));

    # Handler function:
    thread = Thread(target=threadHandler, args=('Some name', 200,));
    thread.start()


#####################################################################

class MyThread(Thread):

    def __init__(self, name: str):
        Thread.__init__(self)
        self.__name = name

    def run(self):
        print("Running thread '{0}'".format(self.__name));
        while (True):
            sleep(1)
            print("Do someting");


def startThread1():
    T = MyThread("SomeTestThread");
    T.start();


#######################################################################

def twoThreads():
    thread1 = None;
    thread2 = None;

    # Handler function:
    def ThreadFunc(count: int,
                   name: str = None) -> None:
        for i in range(1, count + 1):
            print("Thread {0}. Count: ".format(name), i);
            print("T1: {0}, T2: {1}, T1 stopped: {2}, T2 stopped: {3}".
                  format(thread1.isAlive(), thread2.isAlive(), thread1._is_stopped, thread2._is_stopped));
            sleep(1)

    # Handler function:
    thread1 = Thread(target=ThreadFunc, args=(10, "Thread1"));
    thread2 = Thread(target=ThreadFunc, args=(5, "Thread2"));

    sleep(0.7)

    thread1.start()
    thread2.start()


#######################################################################

def OneThread_Stops_Another():
    foreverThread = None;
    watchDogThread = None;

    # ForeverThread function:
    def ForeverThread() -> None:
        while (True):
            print("ForeverThread running");
            sleep(1)

    # WatchDogThread function:
    def WatchDogThread(count: int) -> None:
        iter = 0
        while (True):
            iter += 1;
            sleep(1)
            print("WatchDogThread");
            if (True == foreverThread.isAlive()):
                if (iter >= count):
                    print("foreverThread still running... we should stop it.");
                    foreverThread._set_tstate_lock();
                    foreverThread._stop()
                    print("foreverThread status: ", foreverThread._is_stopped);

    # Creating threads:
    foreverThread = Thread(target=ForeverThread);
    watchDogThread = Thread(target=WatchDogThread, args=(5,));

    foreverThread.start()

    sleep(0.7)

    watchDogThread.start()


#######################################################################

if __name__ == '__main__':
    # runSimpleThread()
    parametrizedThread();
    # startThread1();
    # twoThreads();
    # OneThread_Stops_Another();
