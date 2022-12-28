import subprocess
import sys

# from TII_Experiments.ExecuteCommands.Utilities import comms_utils


class Exec(object):

    @staticmethod
    def execute_command(cmd: str) -> int:
        try:
            proc = subprocess.Popen(cmd.split(), text=True, shell=False,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                print(str(line.rstrip()).strip("b'"))
                sys.stdout.flush()
        except OSError as exc:
            print(f"Can't run process {cmd}. Error: {exc}")
            return False

        proc.wait()
        return proc.poll()

    @staticmethod
    def subprocess_exec_NEW(cmd: str) -> bytes:
        proc = subprocess.Popen(cmd.split(),
                                stdout=subprocess.PIPE,
                                shell=False)
        return proc.communicate()[0]

    def subprocess_exec_OLD(cmd: str) -> bytes:
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                shell=True)
        return proc.communicate()[0]


class Tests(object):

    # soc_version_cmd: str = "cat /proc/cpuinfo | grep 'Revision' | awk '{print $3}'"
    soc_version_cmd: str = "cat /proc/cpuinfo | grep 'vendor_id'| awk '{print $3}'"

    @staticmethod
    def get_cpu_info_NEW():
        soc_version = Exec.subprocess_exec_NEW(Tests.soc_version_cmd).decode('utf-8').strip()
        print(soc_version)

    @staticmethod
    def get_cpu_info_OLD():
        soc_version = Exec.subprocess_exec_OLD(Tests.soc_version_cmd).decode('utf-8').strip()
        print(soc_version)

    @staticmethod
    def get_cpu_info_MY():
        Exec.execute_command(Tests.soc_version_cmd)


if __name__ == '__main__':
    # Tests.get_cpu_info_NEW()
    Tests.get_cpu_info_OLD()

    # Tests.get_cpu_info_MY()
