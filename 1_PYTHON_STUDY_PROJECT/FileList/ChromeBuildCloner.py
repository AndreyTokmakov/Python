
import os
from shutil import copyfile
from pathlib import Path

class Constants(object):
    ''' Build archive file name : '''
    BuildArchiveFile = "Build.zip";
    
    ''' Build server FTP ip address : '''
    BuildServerFtpIPAddress = "100.99.5.84";
    
    ''' FTP user login : '''
    LoginFtpUser = "Administrator";
    
    ''' FTP user password : '''
    LoginFtpPassword = "123!@#QWEqwe";    
    
    ''' Work (Test) directory : '''
    WorkDirectory = "C:\\Projects";
    
    ''' Build archive destination file name : '''
    ArchiveDestionationFile = WorkDirectory + "\\" + BuildArchiveFile;


class ChromeBuildCloner(object):

    def __init__(self, src_dir, dst_dir):
        """Constructor"""
        self.__srcDirectory = src_dir;
        self.__dstDirectory = dst_dir;

    def __copyFile(self, file):
        destFile = file.replace(self.__srcDirectory, self.__dstDirectory);
        #print(destFile);
        os.makedirs(os.path.dirname(destFile), 0o777, True);
        copyfile(file, destFile)

    def __copyFileIfNoExits(self, file):
        destFile = file.replace(self.__srcDirectory, self.__dstDirectory);
        destDir = os.path.dirname(destFile)

        dirHandle = Path(destDir)
        if False == dirHandle.is_dir():
            os.makedirs(destDir, 0o777, True);

        fileHandle = Path(destFile)
        if False == fileHandle.is_file():
            copyfile(file, destFile)        

    def __listFiles(self, sourceDir):
        fileList = list();
        rootPath = os.path.abspath(os.path.join(sourceDir, os.pardir))
        for (root, directories, files) in os.walk(sourceDir):
            for file in files:
                filePath = os.path.join(os.path.relpath(root, rootPath), file);
                fileList.append(rootPath + "\\" + filePath);
        return fileList

    def CloneDirectory(self):
        files = self.__listFiles(self.__srcDirectory)
        progress = 0;
        total = len(files);
        print(total)
        n = int(total / 100);
        for file in files:
            self.__copyFileIfNoExits(file);
            total = total - 1;
            if 0 == total % n:
                print (progress) 
                progress = progress + 1;
            #self.__copyFile(file);


if __name__ == '__main__':

    cloner = ChromeBuildCloner("R:\\Projects\\browser\\src\\chrome", "C:\\Temp\ZIP\\chrome");
    cloner.CloneDirectory()