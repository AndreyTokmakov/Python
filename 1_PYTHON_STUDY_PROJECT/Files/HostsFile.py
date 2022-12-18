
class HostsWrapper(object):
    # HostsWrapper constructor:
    def __init__(self, filePath: str = None) -> None:
        self.__hosts_file_path = filePath;
        self.__origFileLines = list();
    
    def __ReadFile(self):
        with open(self.__hosts_file_path) as file:
            for line_terminated in file:
                self.__origFileLines.append(line_terminated.rstrip('\n'));    
                
    def Test(self):
        self.__ReadFile();
        for line in self.__origFileLines:
            print(line);


if __name__ == '__main__':
    
    filePath = "R:\\Temp\\FILES\\hosts";
    wrapper = HostsWrapper(filePath);
    wrapper.Test();
