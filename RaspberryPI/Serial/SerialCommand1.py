
import serial

if __name__ == '__main__':

    # python -m serial.tools.list_ports
    ser = serial.Serial("/dev/ttyS0", baudrate=9600, timeout=0.1)
    ser.flush()
    print(ser)
    while True:
        line = ser.readline().decode().strip()
        if line:
            print(line)

    ser.close()
