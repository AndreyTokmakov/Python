import subprocess
import sys
from typing import List


def Exec(cmd: str) -> str:
    output = subprocess.Popen(cmd.split(), text=True, stdout=subprocess.PIPE)
    stdout, _ = output.communicate()
    return stdout


def Exec2(cmd: str):
    try:
        proc = subprocess.Popen(cmd.split(),
                                text=True,
                                shell=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        output: List = []
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            output.append(line.rstrip())

    except OSError as exc:
        print("Can't run process. Error code = {0}".format(exc))
        return False

    proc.wait()
    return output


if __name__ == '__main__':
    # print(Exec("ls -lar /home/andtokm"))

    output = Exec2("ls -lar /home/andtokm")
    for l in output:
        print(l)




    # Exec("ls -lar /root")

    # print(Exec("service lm-sensors status"))

    # print(Exec("iptables -L -t filter"))

    pass
