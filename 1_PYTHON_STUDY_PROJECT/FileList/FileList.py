import os
import re
import sys
import zipfile
import bz2
import gzip
import time
from shutil import copyfile

blackList = list()
blackList.append(".cc")
blackList.append(".cpp")
blackList.append(".h")
blackList.append(".git")
blackList.append(".obj")
blackList.append(".stamp")
blackList.append(".pdb")
blackList.append(".lib")
blackList.append(".ninja")
blackList.append(".rc")
blackList.append(".res")
blackList.append(".exp")
blackList.append(".ilk")
blackList.append(".7z")
blackList.append(".recompile")
blackList.append(".pch")
blackList.append(".out")

blackListFolders = list();
blackListFolders.append("swarming_client\\example\\payload")

whileList = list()
whileList.append(".dll")
whileList.append(".exe")


def isTest(file):
    if "swarming_client\\example\\payload" in file:
        return False
    for blackListEntry in blackListFolders:
        if blackListEntry in file:
            return True;
    for blackListEntry in blackList:
        # if blackListEntry in file:
        if file.endswith(blackListEntry):
            # print ("Black listed : ", file)
            return True;
    return False


def isFileValid(file):
    for whiteListEntry in whileList:
        # if whiteListEntry in file:
        if file.endswith(whiteListEntry):
            # print ("White listed : ", file)
            return True
    for blackListEntry in blackListFolders:
        if blackListEntry in file:
            return False
    for blackListEntry in blackList:
        # if blackListEntry in file:
        if file.endswith(blackListEntry):
            # print ("Black listed : ", file)
            return False;
    return True


def FileList1(sourceFolder):
    fileList = list();
    relroot = os.path.abspath(os.path.join(sourceFolder, os.pardir))
    print(relroot);
    for (root, directories, files) in os.walk(sourceFolder):
        for file in files:
            filePath = os.path.join(os.path.relpath(root, relroot), file);
            # if isTest(filePath):
            if isFileValid(filePath):
                fileList.append(relroot + "\\" + filePath);
    return fileList


def getSize(filePath):
    return os.path.getsize(filePath);


def ZipFiles(fileList, archiveFile):
    zipf = zipfile.ZipFile(archiveFile, 'w', zipfile.ZIP_DEFLATED)
    for file in fileList:
        zipf.write(file)
    zipf.close()


'''
def f3(fn, dest):
    with open(fn, 'rb') as f:
         zf = zipfile.ZipFile(f)
         futures = []
        with concurrent.futures.ProcessPoolExecutor() as executor:
            for member in zf.infolist():
                 futures.append(executor.submit(unzip_member_f3, fn, member.filename,dest,))
        total = 0
           for future in concurrent.futures.as_completed(futures):
            total += future.result()
    return total
'''


def GZipTest():
    inF = open("R:\\Projects\\Python\\ZipArchiver\\Zipper\\Zipper.py", 'rb')
    s = inF.read()
    inF.close()

    outF = gzip.GzipFile("R:\\Projects\\Test.gz", 'wb')
    outF.write(s)
    outF.close()


def CopyFiles(fileList):
    for file in fileList:
        destFile = file.replace("R:\\Projects\\browser", "R:\\Projects\\browser2");
        os.makedirs(os.path.dirname(destFile), 0o777, True);
        # print (file)
        # print (destFile)
        copyfile(file, destFile)


def FileListTest(sourceFolder):
    count = 0;
    fileList = list();
    relroot = os.path.abspath(os.path.join(sourceFolder, os.pardir))
    print(relroot);
    for (root, directories, files) in os.walk(sourceFolder):
        for file in files:
            filePath = os.path.join(os.path.relpath(root, relroot), file);
            # if isTest(filePath):
            # if isFileValid(filePath):
            #    fileList.append(relroot + "\\" + filePath);
            count = count + 1;
    print(count)
    return fileList


#####################################

if __name__ == '__main__':
    # GZipTest()

    # sourceFolder = sys.argv[1]
    # zipFile = sys.argv[2]

    start_time = time.time()
    FileListTest("R:\\Projects\\browser\\src");
    print("--- %s seconds ---" % (time.time() - start_time))

    '''
    sourceFolder = "R:\\Projects\\browser\\src";
    sourceFolder2 = "R:\\Projects\\browser\\src\\base\\allocator";
    
    
    fileList = FileList1(sourceFolder)
    CopyFiles(fileList);
    '''

    # zipFile = "R:\\Projects\\Folder.zip";
    # ZipFiles(fileList, zipFile);

    '''
    
    resultsFile = open("C:\\Temp\\ZIP\\results.txt",'w')
    totalSize = 0;
    
    for file in fileList:
        #print(file)
        resultsFile.write(file + "\n")
        totalSize = totalSize + getSize(file);
        
    print(len(fileList));
    print(totalSize)

    resultsFile.close() 
   
 '''
