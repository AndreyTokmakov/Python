import subprocess, shlex
import sys
import time
from pathlib import Path
from typing import List


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
    proc_cmd, grep_cmd = 'cat /proc/cpuinfo', 'grep vendor_id'

    proc1 = subprocess.Popen(proc_cmd.split(),
                             stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(grep_cmd.split(),
                             stdin=proc1.stdout,
                             stdout=subprocess.PIPE)
    output = proc2.communicate()[0]
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
    command: str = "cat /proc/cpuinfo | grep vendor_id"
    sub_commands: List[str] = list(map(str.strip, command.split('|')))

    proc_list: List[subprocess.Popen] = []
    for cmd in sub_commands:
        proc = subprocess.Popen(cmd.split(),
                                stdin=None if not proc_list else proc_list[-1].stdout,
                                stdout=subprocess.PIPE)
        proc_list.append(proc)

    output = proc_list[-1].communicate()[0]
    print(output)


def manual_linux_pipe_emulation2():
    command: str = "cat /proc/cpuinfo | grep apicid | grep 3"
    sub_commands: List[str] = list(map(str.strip, command.split('|')))

    stdout = None
    for cmd in sub_commands:
        proc = subprocess.Popen(cmd.split(),
                                stdin=stdout,
                                stdout=subprocess.PIPE)
        stdout = proc.stdout

    output = proc.communicate()[0]
    print(output)


def manual_linux_pipe(command: str):
    sub_commands: List[str] = list(map(str.strip, command.split('|')))
    stdout, proc = None, None
    for cmd in sub_commands:
        proc = subprocess.Popen(cmd.split(), stdin=stdout, stdout=subprocess.PIPE)
        stdout = proc.stdout

    return proc.communicate()[0]


if __name__ == '__main__':
    # Exec("ls -lar")
    # Exec2()

    # Test()
    # Test2()
    # Test3()

    # experiments()
    # call_grep_without_shell()
    # call_grep_awk_without_shell()

    # manual_linux_pipe_emulation()
    # manual_linux_pipe_emulation2()

    # result = manual_linux_pipe("cat /proc/cpuinfo | grep vendor_id | awk '{print $3}'")
    result = manual_linux_pipe("ps aux | grep libexec | grep color")
    print(result)
