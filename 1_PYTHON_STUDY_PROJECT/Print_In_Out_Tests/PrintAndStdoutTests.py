
import sys
import time

def clear_line():
    sys.stdout.write("\033[F") #back to previous line
    sys.stdout.write("\033[K") #clear line
    sys.stdout.flush();

def PrintAndErase():
    print("Downloading build archive....");
    for i in range(10):
        print(i, "%");
        time.sleep(1)
        clear_line();
    print("Done")

if __name__ == '__main__':
    
    PrintAndErase();