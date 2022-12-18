import os
import re
import sys
import zipfile
import bz2
import gzip
import time
from shutil import copyfile

count = 0;

class FileListingTests(object):
    
    count = 0;
    
    def __init__(self, srcDirectory, dstArchiveFile):
        """Constructor"""
        self.__srcDirectory = srcDirectory;
        self.__dstArchiveFile = dstArchiveFile;

        self.__InitFoldersWhiteList();
        self.__InitFoldersBlackList();
        self.__InitFileTypeBlackList();
        self.__InitFileTypeWhiteList();
        
        self.__fileList = list();  

    def __InitFoldersWhiteList(self):
        self.__whiteListFolders = list();
        self.__whiteListFolders.append("src\\third_party\\accessibility-audit")
        self.__whiteListFolders.append("src\\third_party\\chaijs")
        self.__whiteListFolders.append("src\\third_party\\tlslite")
        self.__whiteListFolders.append("src\\third_party\\zlib")

    def __InitFoldersBlackList(self):
        self.__blackListFolders = list();
        self.__blackListFolders.append("swarming_client\\example\\payload")
        self.__blackListFolders.append(".git")
        self.__blackListFolders.append(".vs");
        self.__blackListFolders.append("clang_newlib_x64\\");
        self.__blackListFolders.append("irt_x64\\");
        self.__blackListFolders.append("nacl_test_data\\");
        self.__blackListFolders.append("newlib_pnacl\\");
        self.__blackListFolders.append("src\\android_webview");
        self.__blackListFolders.append("src\\native_client\\toolchain");
        self.__blackListFolders.append("src\\apps");
        self.__blackListFolders.append("src\\ash");
        self.__blackListFolders.append("src\\build");
        self.__blackListFolders.append("src\\build_overrides");
        self.__blackListFolders.append("src\\buildtools");
        self.__blackListFolders.append("src\\cc");
        self.__blackListFolders.append("src\\chrome_elf");
        self.__blackListFolders.append("src\\chromecast");
        self.__blackListFolders.append("src\\chromeos");
        self.__blackListFolders.append("src\\cloud_print");
        self.__blackListFolders.append("src\\content");
        self.__blackListFolders.append("src\\courgette");
        self.__blackListFolders.append("src\\crypto");
        self.__blackListFolders.append("src\\dbus");
        self.__blackListFolders.append("src\\device");
        self.__blackListFolders.append("src\\docs");
        self.__blackListFolders.append("src\\gin");
        self.__blackListFolders.append("src\\google_apis");
        self.__blackListFolders.append("src\\google_update");
        self.__blackListFolders.append("src\\gpu");
        self.__blackListFolders.append("src\\headless");
        self.__blackListFolders.append("src\\infra");
        self.__blackListFolders.append("src\\ios");
        self.__blackListFolders.append("src\\ipc");
        self.__blackListFolders.append("src\\jingle");
        self.__blackListFolders.append("src\\mash");
        self.__blackListFolders.append("src\\media");
        self.__blackListFolders.append("src\\native_client_sdk");
        self.__blackListFolders.append("src\\pdf");
        self.__blackListFolders.append("src\\ppapi");
        self.__blackListFolders.append("src\\printing");
        self.__blackListFolders.append("src\\remoting");
        self.__blackListFolders.append("src\\rlz");
        self.__blackListFolders.append("src\\sandbox");
        self.__blackListFolders.append("src\\services");
        self.__blackListFolders.append("src\\skia");
        self.__blackListFolders.append("src\\sql");
        self.__blackListFolders.append("src\\storage");
        self.__blackListFolders.append("src\\styleguide");
        self.__blackListFolders.append("src\\third_party")
        self.__blackListFolders.append("src\\ui");
        self.__blackListFolders.append("src\\url");
        self.__blackListFolders.append("src\\v8");

    def __InitFileTypeBlackList(self):
        self.__blackListTypes  = list();
        self.__blackListTypes.append(".cc")
        self.__blackListTypes.append(".cpp")
        self.__blackListTypes.append(".h")
        self.__blackListTypes.append(".obj")
        self.__blackListTypes.append(".stamp")
        self.__blackListTypes.append(".pdb")
        self.__blackListTypes.append(".lib")
        self.__blackListTypes.append(".ninja")
        self.__blackListTypes.append(".rc")
        self.__blackListTypes.append(".res")
        self.__blackListTypes.append(".exp")
        self.__blackListTypes.append(".ilk")
        self.__blackListTypes.append(".7z")
        self.__blackListTypes.append(".recompile")
        self.__blackListTypes.append(".pch")
        self.__blackListTypes.append(".out")
        self.__blackListTypes.append(".res_ms_rc")    

    def __InitFileTypeWhiteList(self):     
        self.__whiteListTypes = list(); 
        self.__whiteListTypes.append(".dll")

    def __isFileValid(self, file):
        for whiteListEntry in self.__whiteListFolders:
            if whiteListEntry in file:
                return True;
        for blackListEntry in self.__blackListFolders:
            if blackListEntry in file:
                return False;
        for whiteListEntry in self.__whiteListTypes:
            if file.endswith(whiteListEntry):
                return True;      
        for blackListEntry in self.__blackListTypes:
            if file.endswith(blackListEntry):
                return False;
        return True        
      
    def FileListing_Walk(self, sourceDir):
          
        rootPath = os.path.abspath(os.path.join(sourceDir, os.pardir))
        for (root, directories, files) in os.walk(sourceDir):
            for file in files:
                filePath = os.path.join(os.path.relpath(root, rootPath), file); 
                self.__fileList.append(rootPath + "\\" + filePath);
                #if self.__isFileValid(filePath):
                    #self.__fileList.append(rootPath + "\\" + filePath);

    def FileListing_Scandir(self, sourceFolder):
        try:
            for entry in os.scandir(sourceFolder):
                filePath = os.path.join(sourceFolder, entry.name)
                if entry.is_dir():
                    self.FileListing_Scandir(filePath);        
                else:
                    self.__fileList.append(filePath);
        except FileNotFoundError as exc:
            pass;
        
    def Info(self):
        print("Files : ", len(self.__fileList));

if __name__ == '__main__':
    
    dir = "R:\\Projects\\browser\\src";
    tester = FileListingTests(dir, "");
    
    start = time.time();
    
    tester.FileListing_Scandir(dir);
    #tester.FileListing_Walk(dir);
    
    end = time.time()
    print("Elapsed time : %s seconds ---" % (end - start))
    tester.Info();


