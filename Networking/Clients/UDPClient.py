import socket


def simple_test() -> None:
    pass


if __name__ == '__main__':
    port: int = 52525
    # host: str = "192.168.57.54"
    host: str = "192.168.1.2"   # When connected to Comms_Sleeve WiFi point
    data: str = "SOME_TEST_DATA"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
    sock.sendto(bytes(data, "utf-8"), (host, port))
