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
    # cmd: bytes = b"ps axf\r\n"
    cmd: bytes = b"ls -lar\r\n"

    bytes_to_read: int = 256

    with serial.Serial('/dev/ttyUSB0', 115200, timeout=0.1) as ser:
        print(ser.name, ser.is_open)
        ser.write(cmd)

        while True:
            data = ser.read(bytes_to_read)
            # print(f'----------------------------- {len(data)} ------------------------------------')
            print(data)
            if bytes_to_read > len(data):
                break


if __name__ == '__main__':
    # open_port()
    # open_port_2()
    send_command()
