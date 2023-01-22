import socket


def send_file(file_path: str) -> None:
    with open(file_path, "rb") as file:
        content = file.read()

    host, port = "0.0.0.0", 52525
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((host, port))
        sock.sendall(content)

    print(len(content))


if __name__ == "__main__":
    # send_file("/home/andtokm/DiskS/Temp/Folder_For_Testing/src_file.txt")
    send_file("/home/andtokm/Pictures/1/1.png")

