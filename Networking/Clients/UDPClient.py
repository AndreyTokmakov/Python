import socket


def simple_test() -> None:
    pass


if __name__ == '__main__':
    port: int = 52525
    host: str = "127.0.0.1"
    data: str = "SOME_TEST_DATA"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
    sock.sendto(bytes(data, "utf-8"), (host, port))
