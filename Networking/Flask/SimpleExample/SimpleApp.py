from flask import Flask

server = Flask(__name__)


@server.route('/')
def index():
    return 'Index Page'


@server.route('/hello')
def hello():
    return 'Hello, World'


@server.route('/test')
def test():
    return 'Hello, World'


if __name__ == '__main__':
    server.run(host="0.0.0.0", port=52525, debug=True)
