import datetime

import pika

HOST: str = "0.0.0.0"
credentials = pika.PlainCredentials('admin', 'qwerty12345')


def publish():
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.queue_declare(queue='hello')
        msg = f'Hello from {datetime.datetime.utcnow()}'
        channel.basic_publish(exchange='',
                              routing_key='hello',
                              body=bytes(msg, encoding='utf8'))


if __name__ == '__main__':
    publish()
