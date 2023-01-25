import time

import pika

credentials = pika.PlainCredentials('admin', 'admin')


def simple_connection():
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        print(channel)
        # time.sleep(30)


def create_queue():
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()

        channel.queue_declare(queue='hello')
        channel.basic_publish(exchange='', routing_key='hello', body=b'Hello W0rld!')
        print(" [x] Sent 'Hello World!'")


if __name__ == '__main__':
    # simple_connection()
    create_queue()

    pass
