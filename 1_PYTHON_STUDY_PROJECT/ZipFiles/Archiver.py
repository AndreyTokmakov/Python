#============================================================================
# Name        : Archiver
# Created on  : March 19, 2020
# Author      : Tokmakov Andrey
# Version     : 1.0
# Copyright   : Your copyright notice
# Description : Archiver class implementation
#============================================================================

import os
import sys
import zipfile
import time
from shutil import copyfile
#from pathlib import Path

class FileToArchive():
    
    # Archiver class constructor:
    def __init__(self,
                 entry: os.DirEntry,
                 source_dir: str):
        self.__entry = entry;
        self.__source_dir = source_dir;
        
    @property    
    def path(self)-> str:
        return self.__entry.path;

    @property    
    def source_dir(self)-> str:
        return self.__source_dir;
  
    def is_dir(self)-> bool:
        return self.__entry.is_dir();


# Archiver class:
class Archiver(object):
    
    # Archiver class constructor:
    def __init__(self,
                 folders: list,
                 destFile: str):
        
        # Files list to be compressed:
        self.__fileList = list();
        
        # Files list to be compressed:
        self.__sourceDirs = list();
        for dir in folders:
            self.__sourceDirs.append(dir);
        
        # Files list to be compressed:
        self.__dstArchiveFile = destFile;        
        
    # Initialize file list: 
    def __scanDirectoryFileList(self,
                                sourceFolder: str):
        try:
            for entry in os.scandir(sourceFolder):
                fileEntry = FileToArchive(entry, sourceFolder);
                if entry.is_dir():
                    self.__scanDirectoryFileList(fileEntry.path);        
                else:
                    #if self.__isFileValid(filePath):
                    print(fileEntry.path, "      ", fileEntry.source_dir)
                    self.__fileList.append(fileEntry);
        except FileNotFoundError as exc:
            print(exc);
            pass;      
        
    # Initialize file list: 
    def __initFileList(self):
        for folder_path in self.__sourceDirs:
            self.__scanDirectoryFileList(folder_path);
    
    # Compress:
    def Compress(self):
        
        self.__initFileList();
        print("Files to compress: {0}".format(len(self.__fileList)));
        sys.stdout.flush();

        zipfFile = zipfile.ZipFile(self.__dstArchiveFile, 'w', zipfile.ZIP_STORED)
        progress = 0;
        total = len(self.__fileList);
        n = int(total / 100);
        for file in self.__fileList:
            zipfFile.write(file.path)
            total = total - 1;
            if n != 0 and 0 == total % n:
                print (progress);
                sys.stdout.flush();
                progress = progress + 1;
        zipfFile.close()
    
                
    def Extact(self,
               archiveFile,
               destination,
               param):       
        with zipfile.ZipFile(archiveFile) as zip:
            for zip_info in zip.infolist():
                print(zip_info.filename);
                #zip_info.filename = zip_info.filename.replace(param, "")
                zip_info.filename = os.path.basename(zip_info.filename)
                print(zip_info.filename);
                zip.extract(zip_info, destination)  
        
        
        
if __name__ == '__main__':
    
    #archiver = Archiver(("S:\\chromium\\src\\ash",),  "S:\\Archive.zip");
    archiver = Archiver(("R:\\Temp\\HTML",),  "S:\\HTML.zip");
    # archiver.Compress()
    archiver.Extact("S:\\HTML.zip", "S:\\HTML", "Temp/HTML");
    
    
    
    
    
    
    
    
    
    
            