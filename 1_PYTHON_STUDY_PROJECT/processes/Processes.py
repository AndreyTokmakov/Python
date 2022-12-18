import wmi
import psutil


def WMI_ProcessList():
    c = wmi.WMI();
    for process in c.Win32_Process():
        print(process.Name, ", Path = ", process.executablepath);


def psUtilTest():
    # for proc in psutil.process_iter():
    #    print(proc.name);
    procs = list(psutil.process_iter());
    executable = "";
    for process in procs:
        name = process.name();
        if "atom.exe" in name:
            try:
                executable = process.exe();
            except Exception as exc:
                executable = exc;
            parent = process.parent();
            if None is not parent:
                print(name, "   ", executable, ",   ", parent.name(), "   ", parent.pid);


def psUtilTest2():
    for process in psutil.process_iter():
        if "atom.exe" in process.name():
            # print(process.children());
            if None == process.parent():
                print(process.name(), "   NONE");
            else:
                print(process.name(), "   OK");


def getParentAtomProcess():
    procs = list(psutil.process_iter());
    for process in procs:
        name = process.name();
        if "atom.exe" in name:
            parent = process.parent();
            if "explorer.exe" in parent.name():
                return process;
    return None;


def KillAtom():
    atom = getParentAtomProcess();
    atom.kill();


########################################################################
if __name__ == '__main__':
    # WMI_ProcessList();
    # psUtilTest();
    psUtilTest2();
    # KillAtom();
