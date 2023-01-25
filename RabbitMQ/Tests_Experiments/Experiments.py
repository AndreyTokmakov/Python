import datetime
import os
import time

import pika

HOST: str = "0.0.0.0"
credentials = pika.PlainCredentials('admin', 'qwerty12345')


def exchange():
    msg = f'Hello from {datetime.datetime.utcnow()}'
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.exchange_declare('test_exchange')
        channel.queue_declare(queue="test_queue")
        channel.queue_bind("test_queue", "test_exchange", "tests")
        channel.basic_publish(exchange="test_exchange",
                              routing_key="tests",
                              body=bytes(msg, encoding='utf8'))

        def callback(ch, method, properties, body):
            print(" [x] Received " + str(body))

        channel.basic_consume('hello',
                              callback,
                              auto_ack=True)

        channel.start_consuming()

        channel.close()
        connection.close()


if __name__ == '__main__':
    exchange()

