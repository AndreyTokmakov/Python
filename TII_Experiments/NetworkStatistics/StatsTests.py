from collections import defaultdict

import psutil
import time
import os
import pandas as pd
from scapy.interfaces import ifaces

UPDATE_TIMEOUT = 1


def get_size(bytes: int):
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024


def get_usage():
    # get the network I/O stats from psutil
    io = psutil.net_io_counters()
    # extract the total bytes sent and received
    bytes_sent, bytes_recv = io.bytes_sent, io.bytes_recv

    print(f'bytes_sent: {bytes_sent}, bytes_recv: {bytes_recv}')


def get_speed():
    # get the network I/O stats from psutil
    io = psutil.net_io_counters()
    # extract the total bytes sent and received
    bytes_sent, bytes_recv = io.bytes_sent, io.bytes_recv

    while True:
        # sleep for `UPDATE_DELAY` seconds
        time.sleep(UPDATE_TIMEOUT)
        # get the stats again
        io_2 = psutil.net_io_counters()
        # new - old stats gets us the speed
        us, ds = io_2.bytes_sent - bytes_sent, io_2.bytes_recv - bytes_recv
        # print the total download/upload along with current speeds
        print(f"Upload: {get_size(io_2.bytes_sent)}   "
              f", Download: {get_size(io_2.bytes_recv)}   "
              f", Upload Speed: {get_size(us / UPDATE_TIMEOUT)}/s   "
              f", Download Speed: {get_size(ds / UPDATE_TIMEOUT)}/s      ", end="\r")
        # update the bytes_sent and bytes_recv for next iteration
        bytes_sent, bytes_recv = io_2.bytes_sent, io_2.bytes_recv


# TODO: use terminal to run it (look better)
def get_usage_per_interface():
    # get the network I/O stats from psutil on each network interface by setting `pernic` to `True`
    io = psutil.net_io_counters(pernic=True)

    while True:
        # sleep for `UPDATE_DELAY` seconds
        time.sleep(UPDATE_TIMEOUT)
        # get the network I/O stats again per interface
        io_2 = psutil.net_io_counters(pernic=True)
        # initialize the data to gather (a list of dicts)
        data = []
        for iface, iface_io in io.items():
            # new - old stats gets us the speed
            upload_speed, download_speed = io_2[iface].bytes_sent - iface_io.bytes_sent, io_2[iface].bytes_recv - iface_io.bytes_recv
            data.append({
                "iface": iface, "Download": get_size(io_2[iface].bytes_recv),
                "Upload": get_size(io_2[iface].bytes_sent),
                "Upload Speed": f"{get_size(upload_speed / UPDATE_TIMEOUT)}/s",
                "Download Speed": f"{get_size(download_speed / UPDATE_TIMEOUT)}/s",
            })
        # update the I/O stats for the next iteration
        io = io_2
        # construct a Pandas DataFrame to print stats in a cool tabular style
        df = pd.DataFrame(data)
        # sort values per column, feel free to change the column
        df.sort_values("Download", inplace=True, ascending=False)
        # clear the screen based on your OS
        os.system("cls") if "nt" in os.name else os.system("clear")
        # print the stats
        print(df.to_string())


if __name__ == '__main__':
    # get_usage()
    get_speed()
    # get_usage_per_interface()
