import socket


def receive_file():
    # dest_file_name: str = "/home/andtokm/DiskS/Temp/Folder_For_Testing/dest_file.txt"
    dest_file_name: str = "/home/andtokm/DiskS/Temp/Folder_For_Testing/1.png"
    host, port = "0.0.0.0", 52525
    buffer_size: int = 8

    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(5)
    conn, addr = sock.accept()

    with open(dest_file_name, "wb") as file:
        while True:
            data = conn.recv(buffer_size)
            bytes_received: int = len(data)
            if 0 == bytes_received:
                break
            # print(data.decode('utf-8'), end='')
            file.write(data)
            if buffer_size > len(data):
                break

    conn.close()
    sock.shutdown(1)
    sock.close()


if __name__ == "__main__":
    receive_file()
