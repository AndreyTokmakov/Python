#!flask/bin/python
from flask import Flask

app = Flask(__name__)


@app.route('/')
def index():
    return "Hello, World!"


@app.before_request
def before():
    print("This is executed BEFORE each request.")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=52525, debug=True)