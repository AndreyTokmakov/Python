
import os
import time

class Test(object):
    
    count = 0

    def listFiles(self, source_dir):
        root_path = os.path.abspath(os.path.join(source_dir, os.pardir))
        for (root, directories, files) in os.walk(source_dir):
            for file in files:
                full_path = root_path + "\\" + os.path.join(os.path.relpath(root, root_path), file)
                self.count = self.count + 1
    
    def listFiles_Scandir(self, source_dir):
        for entry in os.scandir(source_dir):
            full_path = os.path.join(source_dir, entry.name)
            print(full_path, "  ", entry.is_dir(), "  ", os.path.islink(full_path))
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
    
    T = Test()
    start = time.time()
    
    #T.listFiles("C:\\chromium\\chromium\\src");
    #T.listFiles_Scandir("C:\\chromium\\chromium\\src");
    T.listFiles_Scandir("C:\\chromium\\chromium\\src\\native_client\\toolchain\\win_x86\\nacl_x86_glibc")
    
    end = time.time()
    print("Elapsed time : " , end - start)
    T.Info()
