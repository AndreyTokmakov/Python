
import os
from pathlib import Path
from datetime import datetime

DIR_PATH = "S:\\Temp\\Folder_For_Testing";

def GetAttributest_Scandir_LastModified():
    with os.scandir(DIR_PATH) as dir_contents:
        for entry in dir_contents:
            info = entry.stat()
            print(info.st_mtime)
            
def GetAttributest_Path_LastModified():
    for path in Path(DIR_PATH).iterdir():
        info = path.stat()
        print(info.st_mtime)
        
        
def convert_date(timestamp):
    d = datetime.utcfromtimestamp(timestamp)
    formated_date = d.strftime('%d %b %Y')
    return formated_date

def GetAttributest_Scandir_LastModified_Ex():
    for entry in os.scandir(DIR_PATH):
        if entry.is_file():
            info = entry.stat()
            print(f'{entry.name}\t Last Modified: {convert_date(info.st_mtime)}')
            
            
def Get_Dir_Attributes():
    path = "S:\\Temp\\Folder_For_Testing\\MOVE";
    t = os.path.getmtime(path)
    print("modified time: ", t)
    
    stats =  os.stat(path);
    print(stats)
    print(stats.st_mtime_ns)
     
    
    
    
    
    

#############################################
if __name__ == '__main__':
    # GetAttributest_Scandir_LastModified();
    
    # GetAttributest_Path_LastModified();
    
    # GetAttributest_Scandir_LastModified_Ex();
    
    Get_Dir_Attributes();