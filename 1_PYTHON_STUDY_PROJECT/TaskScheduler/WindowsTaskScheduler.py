
import re
import sys
import subprocess;

''' Task class : '''
class Task():

    def __init__(self, 
                 name: str = None,
                 status: str = None,
                 next_run_time: str = None,
                 logon_model: str = None) -> None:
        self.__name = name;
        self.__status = status;
        self.__next_run_time = next_run_time;
        self.__logon_mode = logon_model;

    @property
    def name(self):
        return self.__name;

    @name.setter
    def name(self, value):
        self.__name = value;

    @property
    def status(self):
        return self.__status;

    @status.setter
    def status(self, value):
        self.__status= value;

    @property
    def next_run_time(self):
        return self.__next_run_time;

    @next_run_time.setter
    def next_run_time(self, value):
        self.__next_run_time= value;

    @property
    def logon_model(self):
        return self.__logon_mode;

    @logon_model.setter
    def logon_model(self, value):
        self.__logon_mode= value;

    # Overload toString() method: 
    def __str__(self):
        return "[name: {0}, Status: {1}, NextRun: {2}, Mode: {3}]".\
                format(self.name, self.status, self.next_run_time, self.logon_model)



''' Utilities class : '''
class WindowsTaskSchedulerVerifier(object): 

    def __init__(self) -> None:
        self.__tasks_list = list();

    def __initTasks(self):
        lines = list();
        try:  
            # Running the 'SCHTASKS' command.
            proc = subprocess.Popen("SCHTASKS /Query /FO LIST", 
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.STDOUT,
                                    shell = False);
            while True:
                line = proc.stdout.readline();
                if not line:
                    break;
                lines.append(str(line.rstrip()).strip("b'"));
                sys.stdout.flush();
        except OSError as exc:
            print("Can't run process. Error code = %s", exc);
            return None;

        proc.wait();
        returncode = proc.poll();  
        if (0 != returncode):
            return False;

        self.__tasks_list.clear();
        task = None;
        for line in lines:
            if "TaskName:" in line:
                if None != task:
                    self.__tasks_list.append(task);
                    task = None;

                task = Task(name = line.replace("TaskName:", "").strip());
            elif "Status:" in line:
                task.status = line.replace("Status:", "").strip()
            elif "Next Run Time:" in line:
                task.next_run_time = line.replace("Next Run Time:", "").strip()
            elif "Logon Mode:" in line:
                task.logon_model = line.replace("Logon Mode:", "").strip()

        if None != task:
            self.__tasks_list.append(task);

        # Return TRUE if task list is not empty.
        return 0 != len(self.__tasks_list);

    def test(self):
        for T in self.__tasks_list:
            print(T);

    def __validateName_Equals(self, name: str):
        for task in self.__tasks_list:
            if name == task.name:
                return True;
        return False;

    def __validateName_Contains(self, sub_string: str):
        for task in self.__tasks_list:
            if sub_string in task.name:
                return True;
        return False;

    def __validateName_RegEx(self, pattern: str):
        regex = re.compile(pattern); 
        for task in self.__tasks_list:
            if regex.search(task.name):
                return True;
        return False;    

    def __get_operation_handler(self, expectation: str):
        if 'equals' is expectation:
            return self.__validateName_Equals;
        if 'contains' is expectation:
            return self.__validateName_Contains;
        if 'regex' is expectation:
            return self.__validateName_RegEx;
        return None;

    def _VerifyExpectation(self, 
                           expectation_name, 
                           expectation,
                           variable_expander):
        # condition = variable_expander.Expand(expectation_name);
        condition = expectation_name;
        handler = self.__get_operation_handler(expectation);
        if (None != handler and True == self.__initTasks()):
            return handler(condition);
        return False;

########################################

if __name__ == '__main__':

    taskSchedule = WindowsTaskSchedulerVerifier();
    # result  = taskSchedule._VerifyExpectation("\\\Microsoft\\\XblGameSave\\\XblGameSaveTask", "equals", None);
    result  = taskSchedule._VerifyExpectation('Scan$', "regex", None);
    print(result);