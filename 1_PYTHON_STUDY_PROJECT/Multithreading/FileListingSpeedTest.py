
import os;
import time;

class Test(object):
    
    count = 0;

    def listFiles(self, sourceDir):
        rootPath = os.path.abspath(os.path.join(sourceDir, os.pardir))
        for (root, directories, files) in os.walk(sourceDir):
            for file in files:
                filePath = rootPath + "\\" + os.path.join(os.path.relpath(root, rootPath), file);
                self.count = self.count + 1;
    
    def listFiles_Scandir(self, sourceDir):
        for entry in os.scandir(sourceDir):
            fullPath = os.path.join(sourceDir, entry.name);
            print(fullPath, "  ", entry.is_dir(), "  ", os.path.islink(fullPath));
            if entry.is_dir(follow_symlinks=False):
                self.listFiles_Scandir(entry.path)
                
                
            '''
            if entry.is_dir() and  entry.is_symlink():
                continue;
            elif entry.is_dir():
                self.listFiles_Scandir(fullPath);
            else:
                self.count = self.count + 1;
            '''
    
    def Info(self):
        print(self.count)

if __name__ == '__main__':
    
    T = Test();
    start = time.time();
    
    #T.listFiles("C:\\chromium\\chromium\\src");
    #T.listFiles_Scandir("C:\\chromium\\chromium\\src");
    T.listFiles_Scandir("C:\\chromium\\chromium\\src\\native_client\\toolchain\\win_x86\\nacl_x86_glibc");
    
    end = time.time();
    print("Elapsed time : " , end - start);
    T.Info()
