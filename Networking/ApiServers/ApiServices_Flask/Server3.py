# app.py
from flask import Flask, render_template, jsonify

app = Flask(__name__)


# Create a URL route in our application for "/"
@app.route('/')
def home():
    """
    This function just responds to the browser ULR
    localhost:5000/
    :return:        the rendered template 'home2.html'
    """
    # return render_template('C:\\Projects\\Python\\Networking\\ApiWithSwagger\\home2.html')
    return render_template('home.html')


@app.route('/hello/', methods=['GET', 'POST'])
def welcome():
    return "Hello World!"


'''
http://localhost:52525/123 ---> 
'''


@app.route('/<int:number>/')
def incrementer(number):
    return f'Incremented number is {number + 1}'


'''
http://localhost:52525/Jonh ---> 
'''


@app.route('/<string:name>/')
def hello(name):
    return f'Hello {name}'


@app.route('/get_json/')
def jet_json_method():
    return jsonify({'name': 'Jimit',
                    'address': 'India'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=52525, debug=True)
