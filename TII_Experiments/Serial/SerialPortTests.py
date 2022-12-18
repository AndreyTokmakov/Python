import serial


def open_port():
    ser = serial.Serial('/dev/ttyUSB0')
    print(ser.name)
    ser.write(b'hello')
    ser.close()


def open_port_2():
    with serial.Serial('/dev/ttyUSB0', 115200) as ser:
        print(ser.name, ser.is_open)
        ser.write(b'hello')
        ser.close()


def send_command():
    with serial.Serial('/dev/ttyUSB0', 115200, timeout=1) as ser:
        print(ser.name, ser.is_open)
        ser.write(b'ps axf\r\n')
        data = ser.read(1000)
        print(data)


if __name__ == '__main__':
    # open_port()
    # open_port_2()
    send_command()
