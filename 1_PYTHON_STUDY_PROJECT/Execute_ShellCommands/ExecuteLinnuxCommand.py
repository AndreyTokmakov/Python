import subprocess, shlex
import sys
import time
from pathlib import Path


def Exec(cmd: str):
    try:
        proc = subprocess.Popen(cmd.split(),
                                text=True,
                                shell=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = str(line.rstrip()).strip("b'")
            print(line)
            sys.stdout.flush()

    except OSError as exc:
        print("Can't run process. Error code = {0}".format(exc))
        return False

    proc.wait()
    return proc.poll()


def Exec2():
    cmd = 'ping -c 5 localhost'
    ping_cmd = subprocess.Popen(shlex.split(cmd),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    while True:
        return_code = ping_cmd.poll()
        print("Return code: {}".format(return_code))

        if return_code is not None:
            break
        else:
            time.sleep(1)
            print("Command in progress...\n")

    print("Command completed with return code: {}".format(return_code))
    print("Command output: {}".format(ping_cmd.stdout.read()))


def Test():
    # subprocess.call(["ls" , "-l"])
    # iptables -L -t filter

    # process_output = subprocess.run(['ls', '-lar'], capture_output=True)
    process_output = subprocess.run(['iptables', '-L', '-t', 'filter'], capture_output=True)

    print(str(process_output).strip())


def Test2():
    out = subprocess.Popen(['ls', '-l', '.'],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    print(stdout)
    print(stderr)


def Test3():
    output = subprocess.Popen(['ls', '-l',  Path.home()],  text=True, stdout=subprocess.PIPE)
    stdout, _ = output.communicate()
    print(stdout)


if __name__ == '__main__':
    Exec("ls -lar")
    # Exec2()

    # Test()
    # Test2()
    # Test3()
