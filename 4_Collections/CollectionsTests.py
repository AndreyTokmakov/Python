
if __name__ == '__main__':
    
    input = list();
    

    input.append("File1");
    input.append("File2");
    input.append("File3");
    input.append("File4");
    input.append("File5");
    input.append("File6");
    input.append("File7");
    input.append("File8");
    input.append("File9");

    # for F in files:
    #    print(F);
    
    size = 3;
    input_size = len(input);
    slice_size = int(input_size / size);
    remain = int(input_size % size);
    result = []
    iterator = iter(input)
    for i in range(size):
        result.append([])
        for j in range(slice_size):
            result[i].append(next(iterator))
        if remain:
            result[i].append(next(iterator))
            remain -= 1
            
    for block in result:
        print(block);