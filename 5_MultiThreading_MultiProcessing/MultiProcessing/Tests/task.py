import sys
import time

if __name__ == '__main__':
    for i in range(10):
        print(i, ' ', end='', flush=True)
        time.sleep(0.1)

    sys.exit(0)
