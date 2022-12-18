import connexion
from flask import (
    Flask,
    render_template
)

# Create the application instance
# app = Flask(__name__, template_folder="templates")


# Create the application instance
app = connexion.App(__name__, specification_dir='./')

# Read the swagger.yml file to configure the endpoints
app.add_api('swagger.yml')


@app.route("/hello")
def hello_world():
    return "Hello, World!"


# Create a URL route in our application for "/"
@app.route('/')
def home():
    """
    This function just responds to the browser ULR
    localhost:5000/
    :return:        the rendered template 'home2.html'
    """
    # return render_template('C:\\Projects\\Python\\Networking\\ApiWithSwagger\\home2.html')
    return render_template('home2.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
