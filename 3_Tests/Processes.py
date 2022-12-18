import subprocess
import sys


def Exec(cmd: str):
    try:
        proc = subprocess.Popen(cmd, shell=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
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
    return proc.poll()


if __name__ == '__main__':
    Exec("iptables -L -t filter")
    pass
