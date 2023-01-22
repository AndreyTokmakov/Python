from __future__ import annotations

import datetime
import json
from typing import Dict


class NetworkStats:

    def __init__(self):
        self.timestamp: datetime.datetime = datetime.datetime.utcnow()
        self.packets_total: int = 4
        self.icmp_packets: int = 2
        self.tcp_packets: int = 1
        self.udp_packets: int = 1

    # Overload (+) operator:
    def __add__(self, right: NetworkStats) -> NetworkStats:
        result: NetworkStats = NetworkStats()
        result.packets_total = self.packets_total + right.packets_total
        result.icmp_packets = self.icmp_packets + right.icmp_packets
        result.tcp_packets = self.tcp_packets + right.tcp_packets
        result.udp_packets = self.udp_packets + right.udp_packets
        return result

    # Overload (+=) operator:
    def __iadd__(self, right: NetworkStats) -> NetworkStats:
        return self + right

    # Overload (-) operator:
    def __sub__(self, right: NetworkStats) -> NetworkStats:
        result: NetworkStats = NetworkStats()
        result.packets_total = self.packets_total - right.packets_total
        result.icmp_packets = self.icmp_packets - right.icmp_packets
        result.tcp_packets = self.tcp_packets - right.tcp_packets
        result.udp_packets = self.udp_packets - right.udp_packets
        return result

    def clone(self) -> NetworkStats:
        copy: NetworkStats = NetworkStats()
        copy.packets_total = self.packets_total
        copy.icmp_packets = self.icmp_packets
        copy.tcp_packets = self.tcp_packets
        copy.udp_packets = self.udp_packets
        return copy

    # Overload (-=) operator:
    def __isub__(self, right: NetworkStats) -> NetworkStats:
        return self - right

    def __str__(self) -> str:
        return json.dumps({'timestamp': str(self.timestamp),
                           'packets_total': self.packets_total,
                           'tcp_packets': self.tcp_packets,
                           'udp_packets': self.udp_packets,
                           'icmp_packets': self.icmp_packets})

    def __repr__(self) -> str:
        return str(self)

    def toJson(self) -> Dict:
        return {'timestamp': str(self.timestamp),
                'packets_total': self.packets_total,
                'tcp_packets': self.tcp_packets,
                'udp_packets': self.udp_packets,
                'icmp_packets': self.icmp_packets}


message = [
    {
        "timestamp": "2023-01-11 07:14:56.131851",
        "packets_total": 183
    },
]

message1 = {'type': 'network_stat',
            'ip': '192.168.1.5',
            'data':
                [
                    {
                        "timestamp": "2023-01-11 07:14:56.131851",
                        "packets_total": 183
                    },
                    {
                        "timestamp": "2023-01-11 07:14:56.131851",
                        "packets_total": 183
                    },
                ]
            }


def message_to_json(input_message):
    json_msg = json.dumps(input_message)
    print(json_msg)

    msg = json.loads(json_msg)
    print(msg)
    print(type(msg))


def parse_test_1():
    stats = NetworkStats()

    msg = {'type': 'network_stat',
           'ip': '127.0.0.1',
           'data': stats.toJson()
           }

    data_to_send = json.dumps(msg)
    # print(data)

    request: Dict = json.loads(data_to_send)
    print(request)

    data = request['data']
    print(data)
    print(data['timestamp'])
    print(data['packets_total'])
    print(data['tcp_packets'])


if __name__ == "__main__":
    # message_to_json(message)
    # message_to_json(message1)
    parse_test_1()
