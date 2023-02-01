import datetime
import json
from typing import Any

import pika


class Client(object):
    EXCHANGE_CHANNEL: str = 'dcube'

    def __init__(self,
                 host: str):
        self.host: str = host

        credentials = pika.PlainCredentials('admin', 'qwerty12345')
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.host,
                                                                            credentials=credentials))
        self.channel = self.connection.channel()

        # declare fanout exchange
        self.channel.exchange_declare(exchange=Client.EXCHANGE_CHANNEL,
                                      exchange_type='fanout')

    def close(self) -> Any:
        self.channel.close()
        return self.connection.close()

    def __del__(self):
        self.close()

    def send(self, message: str):
        declaration: Any = self.channel.queue_declare(queue='', exclusive=True)
        # TODO: Check result

        response_queue: str = declaration.method.queue

        def on_response(ch, method, props, body):
            print(f"Has some:\n{ch}\n{body}\n{props}")
            self.channel.stop_consuming()

        self.channel.basic_consume(queue=response_queue,
                                   on_message_callback=on_response,
                                   auto_ack=True)

        print(f'Message send: {message}, Response queue: {response_queue}')
        self.channel.basic_publish(exchange=Client.EXCHANGE_CHANNEL,
                                   routing_key='',
                                   properties=pika.BasicProperties(reply_to=response_queue),
                                   body=bytes(message, encoding='utf8'))

        self.channel.start_consuming()


if __name__ == '__main__':
    rabbitmq_host: str = "0.0.0.0"
    client = Client(rabbitmq_host)

    request = {"servers": ["10.10.10.2"], "type": "ping"}

    client.send(json.dumps(request))
