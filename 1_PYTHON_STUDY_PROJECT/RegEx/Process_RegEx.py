import sys;
import psutil
import re
import ctypes
import win32con
import win32gui
import win32process
import time;
import psutil;
import subprocess;
from datetime import datetime
from psutil import Process;

# Proc messages storage:
class Process(object):
    
    # Proc class constructor:
    def __init__(self, 
                 pid:  int = 0, 
                 name: str = None,
                 path: str = None,
                 cmd:  str = None) -> None:
        self.process = None;
        self.__name = name;                 
        self.__pid = pid;
        self.__path = path;
        self.__cmd = cmd;
        
    # Build Process from psutil.Process instance:
    @staticmethod
    def fromPsUtilProcess(process: psutil.Process):
        proc = Process();
        proc.process_handle = process;
        try:
            proc.pid = process.pid;
        except:
            pass;
        try:
            proc.name = process.name();
        except:
            pass;
        try:
            proc.cmd = process.cmdline();
        except:
            pass;
        try:
            proc.path = process.exe();
        except:
            pass;
        return proc;

    @property
    def name(self):
        return self.__name;

    @name.setter
    def name(self, name: int)-> str:
        self.__name = name;

    @property
    def pid(self):
        return self.__pid;

    @pid.setter
    def pid(self, pid: int)-> int:
        self.__pid = pid;    

    @property
    def path(self):
        return self.__path;

    @path.setter
    def path(self, path: int)-> str:
        self.__path = path;    

    @property
    def cmd(self):
        return self.__cmd;

    @cmd.setter
    def cmd(self, cmd: int)-> str:
        self.__cmd = cmd; 
            
    # Overload toString() method: 
    def __str__(self):
        return "[Name: {0}, Pid: {1}, Path: {2}, Cmd: {3}]". \
                format(self.name, self.pid, self.path, self.cmd);
                
    def compareName(self, process_name: str)-> bool:
        if (None == self.__name):
            return False;
        return (process_name in self.__name);


class ProcessManager(object):

    BROWSER_PROCESS_EXECUTALBE = "atom.exe";
    CHROMEDRIVER_PROCESS_EXECUTALBE = "chromedriver.exe";
    IE_PROCESS_EXECUTALBE = "iexplore.exe";

    # ProcessManager constructor:
    def __init__(self) -> None:
        pass;

    def validateZombiesProcesses(self):
        print("ProcessManager : Validating zombies...");    
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            if (True == process.compareName(self.CHROMEDRIVER_PROCESS_EXECUTALBE)):
                print("ProcessManager : killing zombie {0} process".format(self.CHROMEDRIVER_PROCESS_EXECUTALBE));
                self.killProces(process);
            if (True == process.compareName(self.BROWSER_PROCESS_EXECUTALBE)):
                print("ProcessManager : killing zombie {0} process".format(self.BROWSER_PROCESS_EXECUTALBE));
                self.killProces(process);
            if (True == process.compareName(self.IE_PROCESS_EXECUTALBE)):
                print("ProcessManager : killing zombie {0} process".format(self.IE_PROCESS_EXECUTALBE));
                self.killProces(process);


    def getParentAtomProcess(self):
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            if (True == process.compareName(self.BROWSER_PROCESS_EXECUTALBE)):
                if None is P.parent():
                    return process;
        return None;

    def getParentAtomProcessEx(self, timeout : int = 300):
        endTime = time.time() + timeout;
        while True:
            proc = self.getParentAtomProcess();
            if proc is not None:
                return proc;
            if time.time() > endTime:
                break
        return None;  

    def __isChromedriverAlive(self):
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            if (True == process.compareName(self.CHROMEDRIVER_PROCESS_EXECUTALBE)):
                return True;
        return False;

    def waitForChromedriverStop(self, timeout : int = 300):
        print("ProcessManager : Waiting until chromedriver to be stoped.");
        endTime = time.time() + timeout;
        while True:
            if False == self.__isChromedriverAlive():
                return True;
            if time.time() > endTime:
                return False;  

    def waitForDriverRelaunchAtom(self, timeout : int = 300):
        chromedriver = None;
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            if (True == process.compareName(self.CHROMEDRIVER_PROCESS_EXECUTALBE)):
                chromedriver = process.process_handle;
                break;
        if None == chromedriver:
            return;
        
        print("ProcessManager : Chromedriver.exe process exist. OK");
            
        print("ProcessManager : Waiting until chromedriver stops all its child atom.exe process...");
        endTime = time.time() + timeout;
        while True:
            if 0 == len(chromedriver.children(recursive = True)):
                print("ProcessManager : All child sub process of chromeriver.exe are stopped.");
                break;
            if time.time() > endTime:
                return False;          
            
        print("ProcessManager : Waiting until some atom.exe process will be started again.");
        endTime = time.time() + timeout;
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            if (True == process.compareName(self.BROWSER_PROCESS_EXECUTALBE)):
                print("ProcessManager : Process 'atom.exe' is running. OK");
                return True;
            if time.time() > endTime:
                return False;

    # TODO : Move to ProcessManager
    def runProcess(self, command, envinonment = None, successCode = 0):
        try:
            print("Running command {0}".format(command));
            proc = subprocess.Popen(command, 
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.STDOUT,
                                    env = envinonment,
                                    shell = False);
            '''
            while True:
                line = proc.stdout.readline();
                if not line:
                    break;
                line = str(line.rstrip());
                print(line);
                sys.stdout.flush();
            '''                  
        except OSError as exc:
            self.print("Can't run process. Error code = %s", exc);
            self.print("Command: {0}".format(command));
            return False;
            
        proc.wait();
        returncode = proc.poll();
        if 0 != successCode:
            print("Error code = {0} is configured as success code in this case".format(successCode));
        print("Command finished with return code : {0}".format(returncode));
        if successCode == returncode:
            return True;
        return False;
    
    def KillAtom(self):
        atom_parent_process = self.getParentAtomProcessEx();
        if (None != atom):
           self.killProces(atom_parent_process);

    # Kills the process 
    def killProces(self, 
                   process: Process,
                   include_children: bool = False)-> bool:
        if None == process:
            return False;
        return self.killProcessById(process.pid, include_children);

    
    #
    # killProcessById
    # Kills the running process by its ID.
    #
    def killProcessById(self, 
                        process_id: int,
                        include_children: bool = False)-> bool:
        try:
            process = psutil.Process(pid = process_id);
        except Exception as exc:
            self.print("FIXME: Unexpected error. Method: killProcessById. Info: Failed to get process by id.");
            print(exc);
            return False;
            
        # we found the process handle, now tring to kill it
        try:
            # if 'include_children' flag is set True, then trying to kill 
            # all it children with him (^_^)
            if (True == include_children):
                for child in process.children(recursive = include_children): 
                    child.kill();
                    #child.wait(5);
            process.kill();
            #process.wait(5);
        except Exception as exc:
            self.print("FIXME: Unexpected error. Method: killProcessById. Info: Failed to kill process by id.");
            print(exc);
            return False;
        
        # Exit with TRUE if we able to get here without errors.
        return True;


    """
    Fetches a list of OS processes until it finds a process 
    with a suitable name
    
    Arguments:
        process_name: The name of the process
    Returns:
        Process class instance, in case of success
        None, in cafe of failure or in case if we no such process
        with appropriative name.
    Raises:
        No exceptions shall be raised by this method.
        All of the should be handled inside.
    """
    def getProcessByName(self, process_name: str)-> Process:
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            if (True == process.compareName(process_name)):
                return process;
        return Process(pid = -1);
    
    
    """
    Fetches a list of OS processes until it finds a process 
    with a suitable name
    
    Arguments:
        process_name: The name of the process
    Returns:
        Process class instance, in case of success
        None, in cafe of failure or in case if we no such process
        with appropriative name.
    Raises:
        No exceptions shall be raised by this method.
        All of the should be handled inside.
    """
    def getProcessByNameRe(self, name_match_pattern: str)-> Process:
        pattern = re.compile(name_match_pattern)
        for P in psutil.process_iter():
            process = Process.fromPsUtilProcess(P);
            #if (True == process.compareName(process_name)):
            if pattern.findall(process.name):
                return process;
        return Process(pid = -1);


    # GeRunningProcesses:  
    def GeRunningProcesses(self)-> list:
        procs = list();
        for P in psutil.process_iter():
            procs.append(Process.fromPsUtilProcess(P));
        return procs; 


    # GetProcessIDs:  
    def GetProcessIDs(self, 
                      process_path: str = None)-> list:
        return [proc.pid for proc in self.GeRunningProcesses() if proc.path == process_path]  


    # GetWindowHandles:  
    def GetWindowHandles(self,
                         process_ids):
        hwnds = []
        def EnumerateWindowCallback(hwnd, _):
            _, found_process_id = win32process.GetWindowThreadProcessId(hwnd)
            if found_process_id in process_ids and win32gui.IsWindowVisible(hwnd):
                hwnds.append(hwnd)

        # Enumerate all the top-level windows and call the callback with the hwnd as
        # the first parameter.
        win32gui.EnumWindows(EnumerateWindowCallback, None)
        return hwnds
        

    # GetWindowHandles:  
    def CloseWindowsByPath(self, process_path):
        processManager = ProcessManager();
        start_time = time.time()
        while time.time() - start_time < 40:
            process_ids = processManager.GetProcessIDs(process_path)
            if not process_ids:
                return True
            for hwnd in processManager.GetWindowHandles(process_ids):
                try:
                    win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0);
                except pywintypes.error as error:
                    print(error);
                    # It's normal that some window handles have become invalid.
                    if error.args[0] != winerror.ERROR_INVALID_WINDOW_HANDLE:
                        raise
            time.sleep(0.1)
        print("CloseWindows. Exit with FALSE.");
        return False

##############################################################################################################################################
#                                                             MAIN :                                                                         #
##############################################################################################################################################
if __name__ == '__main__':
    processManager = ProcessManager();

    
    P = processManager.getProcessByName2("[Nn]otepad.exe");
    print(P);
    
