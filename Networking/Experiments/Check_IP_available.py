import socket


def is_ip_available(addr: str) -> bool:
    try:
        socket.gethostbyaddr(addr)
        return True
    except:
        return False


if __name__ == "__main__":
    backend_addr: str = ""
    for addr in ["10.10.10.4", "192.168.1.0"]:
        if is_ip_available(addr):
            backend_addr = addr
            break

    print(backend_addr)