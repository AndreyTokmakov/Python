import pika, sys, os

credentials = pika.PlainCredentials('admin', 'qwerty12345')


def consume_from_exchange():
    exchange_name: str = "test_exchange1"

    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.exchange_declare(exchange=exchange_name, exchange_type='fanout')

        result = channel.queue_declare(queue='', exclusive=True)
        queue_name: str = result.method.queue

        channel.queue_bind(exchange=exchange_name, queue=queue_name)

        def callback(ch, method, properties, body):
            print(f'Message: {body.decode()}')

        channel.basic_consume(queue=queue_name,
                              on_message_callback=callback,
                              auto_ack=True)

        channel.start_consuming()


if __name__ == '__main__':
    consume_from_exchange()
