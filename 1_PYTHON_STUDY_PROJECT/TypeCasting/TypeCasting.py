

if __name__ == '__main__':
    #print("TypeCasting tests:");
    
    strInt = "12d3";
    intVal = 0;
    try:
        intVal = int(strInt);
    except ValueError as exc:
        print("Failed to convert value '", intVal, "' to Integer type");
        
    print(intVal);