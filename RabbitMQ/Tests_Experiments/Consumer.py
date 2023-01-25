import pika, sys, os


credentials = pika.PlainCredentials('admin', 'qwerty12345')


def consume():
    queue_name: str = "my_queue"
    with pika.BlockingConnection(pika.ConnectionParameters(host="0.0.0.0",
                                                           credentials=credentials)) as connection:
        channel = connection.channel()
        channel.queue_declare(queue=queue_name)

        def callback(ch, method, properties, body):
            print(" [x] Received %r" % body)

        channel.basic_consume(queue=queue_name,
                              on_message_callback=callback,
                              auto_ack=True)

        print(' [*] Waiting for messages. To exit press CTRL+C')
        channel.start_consuming()


if __name__ == '__main__':
    try:
        consume()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
