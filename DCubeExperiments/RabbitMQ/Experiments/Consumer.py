import pika, sys, os


credentials = pika.PlainCredentials('admin', 'qwerty12345')


def consume():
    queue_name: str = "dcube"
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.queue_declare(queue=queue_name)

        def callback(ch, method, properties, body):
            print(f'Message: {body.decode()}')

        channel.basic_consume(queue=queue_name,
                              on_message_callback=callback,
                              auto_ack=True)

        print(' [*] Waiting for messages. To exit press CTRL+C')
        channel.start_consuming()


def consume_from_exchange():
    queue_name: str = "dcube"
    exchange: str = "test_exchange1"

    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.queue_declare(queue=queue_name)

        def callback(ch, method, properties, body):
            print(f'Message: {body.decode()}')

        channel.basic_consume(queue=queue_name,
                              on_message_callback=callback,
                              auto_ack=True)

        print(' [*] Waiting for messages. To exit press CTRL+C')
        channel.start_consuming()


if __name__ == '__main__':
    # consume()
    consume_from_exchange()
