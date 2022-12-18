'''
Created on Jul 23, 2020
@author: AndTokm
'''
from pathlib import Path

def CreateDir():
    Path("S:\\Temp\\Folder_For_Testing\\111").mkdir(parents=True, exist_ok=True)

if __name__ == '__main__':
    CreateDir()