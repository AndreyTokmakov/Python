
import socket


def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 52525))

    while True:
        message, address = server_socket.recvfrom(1024)
        print(f'{address}: {message.decode()}')


if __name__ == '__main__':
    server()
