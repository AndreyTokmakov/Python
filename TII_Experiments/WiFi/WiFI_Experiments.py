
from wifi.scan import Cell

def scan(interface: str):
    aps = Cell.all(interface)
    for ap in list(aps):
        print(ap)

    # TODO: To check from cmd
    # >  nmcli dev wifi list

if __name__ == '__main__':
    scan("wlp4s0")
    pass
