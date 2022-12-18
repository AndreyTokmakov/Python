import hashlib

def HashInput():
    inp = input('Enter something: ')
    print(hashlib.sha256(inp.encode('utf-8')).hexdigest())
    
def HashFile():
    buffer = "sdsdsdsdsdsd";
    print(hashlib.sha256(buffer.encode("utf-8")).hexdigest())
    
    
def HashFile2():
    filename = "C:\\Temp\\ATOM_INSTALLER\\atom_office.exe";
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest());

if __name__ == '__main__':
    #HashFile();
    HashFile2();