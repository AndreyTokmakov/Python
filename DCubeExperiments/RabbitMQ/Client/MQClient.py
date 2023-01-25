import datetime
import json
from enum import Enum

import pika
import uuid
from typing import Any, List


class CommandType(str, Enum):
    UNKNOWN = "unknown"
    PING = "ping"
    TIMESTAMP = "timestamp"
    MOTELIST = "motelist"
    RESET = "reset"
    POWER = "power"
    PROGRAM = "program"
    MOTE = "mote"
    MEASUREMENT = "measurement"
    TRACE = "treace"
    REBOOT = "reboot"
    EXPERIMENT = "experiment"
    PROCESS = "process"


class CommandState(str, Enum):
    ON = "on"
    OFF = "off"


class CommandReturn(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    FORMAT = "format"
    MISSING = "missing"
    STOPPED = "stopped"
    RUNNING = "running"


class CommandExe(str, Enum):
    CUSTOM = "custom"
    JAMMING = "jamming"
    BLINKER = "blinker"


class MQClient(object):
    EXCHANGE_CHANNEL: str = 'dcube_exchange_channel'

    def __init__(self,
                 host: str,
                 hostname: str,
                 user_name: str,
                 user_pass: str,
                 servers: List = None):
        # self.logger = logging.getLogger("D-Cube Client")

        self.corr_id: str = ""
        self.destinations: List = []
        self.responses = {}
        # self.hostname = hostname
        self.servers: List = [] if servers is None else servers

        credentials = pika.PlainCredentials(user_name, user_pass)
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=host, credentials=credentials))
        self.channel = self.connection.channel()

        # declare fanout exchange
        self.channel.exchange_declare(exchange=MQClient.EXCHANGE_CHANNEL,
                                      exchange_type='fanout')

    def close(self) -> Any:
        self.channel.close()
        return self.connection.close()

    def on_response(self, ch, method, props, body):
        print(f"{ch}\n{body.decode()}\n{props}")
        self.channel.stop_consuming()

        '''
        if self.corr_id == props.correlation_id:
            response = json.loads(body.decode())
            self.responses[response['name']] = response
            # self.logger.debug("Response received: %r" % response)
            print(f"Response received: {response}")
            if response["name"] in self.destinations:
                # self.logger.debug("%r has responded!" % response["name"])
                print(f"{response['name']} has responded!")
                self.destinations.remove(response["name"])
                if len(self.destinations) == 0:
                    self.channel.stop_consuming()
        '''

    def on_timeout(self):
        print("A timeout has occurred, stopping to listen!")
        # self.logger.debug("A timeout has occurred, stopping to listen!")
        self.channel.stop_consuming()

    # TODO: Refactor ???
    def send(self, command, servers, timeout=45, listen=True):
        self.responses = {}
        self.destinations = list(servers)

        # callback queue
        result = self.channel.queue_declare(queue='',
                                            exclusive=True)
        callback_queue = result.method.queue
        self.channel.basic_consume(queue=callback_queue,
                                   on_message_callback=self.on_response,
                                   auto_ack=True)

        # create correlation id and publish a message with timestamp request
        self.corr_id = str(uuid.uuid4())
        print(f'Command send: {command}')  # self.logger.debug("Command %s send" % command)

        message: str = json.dumps(command)
        self.channel.basic_publish(exchange=MQClient.EXCHANGE_CHANNEL,
                                   routing_key='',
                                   properties=pika.BasicProperties(reply_to=callback_queue,
                                                                   correlation_id=self.corr_id),
                                   body=bytes(message, encoding='utf8'))
        if listen:
            to = self.connection.call_later(timeout, self.on_timeout)
            self.channel.start_consuming()
            self.connection.remove_timeout(to)
            return self.responses
        else:
            return None

    def ping(self, servers=None, listen=True):
        servers = self.servers if servers is None else servers
        command = {"servers": servers, "type": CommandType.PING, "time": str(datetime.datetime.utcnow())}

        self.send(command, servers, listen=listen)
        '''
        if listen:
            r = self.check_responses(servers=servers)
            self.__raise(r)
        '''

    def __del__(self):
        self.close()


if __name__ == '__main__':
    rabbitmq_host: str = "0.0.0.0"
    client = MQClient(rabbitmq_host, "master", "admin", "qwerty12345", servers=['rpi100', 'rpi101'])
    client.ping()

