
import sys;
import time;
import contextlib;

class Closeable(object):
    def close(self):
        print('closed')


if __name__ == '__main__':
    
    try:
        time.sleep(5);
    except SystemExit as exc:
        print("RERER1");
    finally:
        print("RERER2");
    
    with contextlib.closing(Closeable()):
        sys.exit()