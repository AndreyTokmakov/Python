from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11ProbeReq, Dot11ProbeResp

interface_name: str = "wlp4s0"


def handle_packet(pkt):
    print(pkt.summary())


def find_beacons(pkt):
    if pkt.haslayer(Dot11Beacon):
        # print("**** BECKON **** ")
        print(pkt.summary())


def debug(pkt):
    summary: str = str(pkt.summary())

    # dest: str = "F6:8C:EB:27:6C:AA".lower()
    dest: str = "B2:84".lower()

    addr1, addr2, addr3 = pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3
    if (addr1 and dest in addr1) or (addr2 and dest in addr2) or (addr2 and dest in addr2):
        print(summary)


def get_clients(pkt):
    bssid = pkt[Dot11].addr3
    # target_bssid = self.target_bssid
    if bssid and not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
        # if "18:F0:E4:1F:B2:84" in bssid or 'F6:8C:EB:27:6C:AA' in bssid:
        print(bssid, pkt.summary())
        print(pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3)


def start_sniffing():
    # sniff(iface=interface_name, prn=handle_packet)
    # sniff(iface=interface_name, prn=find_beacons)
    # sniff(iface=interface_name, prn=get_clients)
    sniff(iface=interface_name, prn=debug)


# ----------------------------------------------------------------------------------

def execute_command(cmd: str) -> None:
    # os.system(cmd)
    print(cmd)


def restart_interface(func):
    def set_interface_mode(*args, **kwargs):
        execute_command(f"ifconfig {args[0]} down")
        returned_value = func(*args, **kwargs)
        execute_command(f"ifconfig {args[0]} up")
        return returned_value

    return set_interface_mode


@restart_interface
def monitorMode(iface_name: str):
    execute_command(f"iwconfig {iface_name} mode monitor")


@restart_interface
def monitorModeStop(iface_name: str):
    execute_command(f"iwconfig {iface_name} mode managed")


if __name__ == '__main__':
    start_sniffing()

    # monitorMode('wlp4s0')
    # monitorModeStop('wlp4s0')
    pass
