import datetime

import pika, sys, os

credentials = pika.PlainCredentials('admin', 'qwerty12345')
EXCHANGE_CHANNEL: str = 'dcube_exchange_channel'


def send_response(queue_name: str, message: str):
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        # channel.queue_declare(queue=queue_name)
        channel.basic_publish(exchange='',
                              routing_key=queue_name,
                              body=bytes(message, encoding='utf8'))


def consume_from_exchange():
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.exchange_declare(exchange=EXCHANGE_CHANNEL, exchange_type='fanout')

        result = channel.queue_declare(queue='', exclusive=True)
        queue_name: str = result.method.queue

        channel.queue_bind(exchange=EXCHANGE_CHANNEL, queue=queue_name)

        def callback(ch, method, properties, body):
            print(f'Message: {body.decode()}')
            print(f'Channel: {ch}')
            print(f'Method: {method}')
            # print(f'Properties: {properties}\n')
            if isinstance(properties, pika.BasicProperties):
                response_queue: str = properties.reply_to
                print(f'reply_to: {response_queue}')
                send_response(response_queue, f'Response [time: {datetime.datetime.utcnow()}]')
            print()

        channel.basic_consume(queue=queue_name,
                              on_message_callback=callback,
                              auto_ack=True)

        channel.start_consuming()


if __name__ == '__main__':
    consume_from_exchange()
