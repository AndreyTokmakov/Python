import datetime

import pika

HOST: str = "0.0.0.0"
credentials = pika.PlainCredentials('admin', 'qwerty12345')


def publish():
    queue_name: str = "my_queue"
    key: str = "my_queue"

    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.queue_declare(queue=queue_name)
        msg = f'Hello from {datetime.datetime.utcnow()}'
        channel.basic_publish(exchange='',
                              routing_key=key,
                              body=bytes(msg, encoding='utf8'))


def publish_exchange():
    queue_name: str = "my_queue"
    exchange: str = "test_exchange"
    key: str = "tests"

    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()

        channel.exchange_declare(exchange=exchange)
        channel.queue_declare(queue=queue_name)
        channel.queue_bind(queue=queue_name, exchange=exchange, routing_key=key)

        msg = f'Hello from {datetime.datetime.utcnow()}'
        channel.basic_publish(exchange=exchange,
                              routing_key=key,
                              body=bytes(msg, encoding='utf8'))


if __name__ == '__main__':
    # publish()
    publish_exchange()
