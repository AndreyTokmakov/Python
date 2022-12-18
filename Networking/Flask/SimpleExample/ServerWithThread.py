import datetime
import threading
import time

from flask import Flask

server = Flask(__name__)


@server.route('/')
def index():
    return 'Index Page'


@server.route('/hello')
def hello():
    return 'Hello, World'


def task() -> None:
    while True:
        print(datetime.datetime.now())
        print("--------------------")
        time.sleep(1)


if __name__ == '__main__':
    job: threading.Thread = threading.Thread(target=task, args=())
    job.start()

    server.run(host="0.0.0.0", port=52525, debug=True)
