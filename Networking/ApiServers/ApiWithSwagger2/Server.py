from flasgger import Swagger
from flask import Flask, logging

app = Flask(__name__)
Swagger(app)


# ENDPOINT = 1
@app.route('/hello', methods=['GET'])
def helloapp():
    return 'Hello World'


if __name__ == '__main__':
    app.run(debug=True, threaded=True, port=7005)
    file_handler = logging.FileHandler('app.log')
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
