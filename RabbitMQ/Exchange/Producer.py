import datetime

import pika

HOST: str = "0.0.0.0"
credentials = pika.PlainCredentials('admin', 'qwerty12345')


def publish_exchange():
    exchange: str = "test_exchange1"

    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.exchange_declare(exchange=exchange, exchange_type='fanout')

        msg = f'Hello from {datetime.datetime.utcnow()}'
        channel.basic_publish(exchange=exchange,
                              routing_key='',  # Send to queue's of 'test_exchange1' channel
                              body=bytes(msg, encoding='utf8'))


if __name__ == '__main__':
    publish_exchange()
