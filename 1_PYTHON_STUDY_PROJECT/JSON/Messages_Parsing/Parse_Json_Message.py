import json
from typing import Dict

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


if __name__ == "__main__":
    # message_to_json(message)
    message_to_json(message1)
