import socket
import sys


def send_get_response():
    HOST, PORT = "0.0.0.0", 50080
    data = "MESSAGE_FROM_CLIENT"

    # Create a socket (SOCK_STREAM means a TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        sock.sendall(bytes(data + "\n", "utf-8"))

        # Receive data from the server and shut down
        received = str(sock.recv(1024), "utf-8")

    print("Sent:     {}".format(data))
    print("Received: {}".format(received))


def send_request():
    data = "{\"type\": \"request\", \"data\": \"Hello world!\"}"

    # Create a socket (SOCK_STREAM means a TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect(("0.0.0.0", 52525))
        sock.sendall(bytes(data + "\n", "utf-8"))

    print("Sent:     {}".format(data))


def send_request_2():
    data = "{\"type\": \"request\", \"data\": \"Hello world!\"}"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect(("0.0.0.0", 52525))
        sock.sendall(bytes(data + "\n", "utf-8"))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect(("0.0.0.0", 52525))
        sock.sendall(bytes(data + "\n", "utf-8"))


if __name__ == "__main__":
    # send_get_response()

    # send_request()
    send_request_2()
