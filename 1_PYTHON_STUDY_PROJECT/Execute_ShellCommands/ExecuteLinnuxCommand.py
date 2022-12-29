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

    process_output = subprocess.run(['ls', '-lar'], capture_output=True)

    print(str(process_output.stdout))


def Test2():
    out = subprocess.Popen(['ls', '-lar', '.'],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    print(stdout)
    print(stderr)


def Test3():
    output = subprocess.Popen(['ls', '-l', Path.home()], text=True, stdout=subprocess.PIPE)
    stdout, _ = output.communicate()
    print(stdout)


def experiments():
    cmd = 'ls -lar'
    # cmd = 'ps aux | grep python'

    command = cmd.split()
    print(f'command: {command}')

    proc = subprocess.Popen(cmd.split(),
                            text=True,
                            shell=False,
                            # stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    proc.wait()
    print(proc.poll())


def call_grep_without_shell():
    proc_cmd, grep_cmd = 'ps aux', 'grep python'

    p1 = subprocess.Popen(proc_cmd.split(),
                          stdout=subprocess.PIPE)
    p2 = subprocess.Popen(grep_cmd.split(),
                          stdin=p1.stdout,
                          stdout=subprocess.PIPE)

    output = p2.communicate()[0]
    print(output)


def call_grep_awk_without_shell():
    cpuinfo_cmd, grep_cmd, awk_cmd = 'cat /proc/cpuinfo', "grep vendor_id", "awk '{print $3}'"

    p1 = subprocess.Popen(cpuinfo_cmd.split(), stdout=subprocess.PIPE)
    p2 = subprocess.Popen(grep_cmd.split(), stdin=p1.stdout, stdout=subprocess.PIPE)
    p3 = subprocess.Popen(awk_cmd.split(), stdin=p2.stdout, stdout=subprocess.PIPE)

    output = p3.communicate()[0]
    print(output)


soc_version_cmd = "cat /proc/cpuinfo | grep 'Revision' | awk '{print $3}'"


def manual_linux_pipe_emulation():
    cmd: str = "ls -lar /home/andtokm/DiskS/Temp/ | grep db"

    print(cmd.split('|'))


if __name__ == '__main__':
    # Exec("ls -lar")
    # Exec2()

    # Test()
    # Test2()
    # Test3()

    # experiments()
    # call_grep_without_shell()
    # call_grep_awk_without_shell()

    manual_linux_pipe_emulation()