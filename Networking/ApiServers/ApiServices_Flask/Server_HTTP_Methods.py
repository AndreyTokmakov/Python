from flask import (Flask, request)

app = Flask(__name__)

html: str = """<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Application Home Page</title>
    </head>
    <body bgcolor="gray">
        <h2>
            Welcome to my test API server !))
        </h2>
    </body>
</html>"""


@app.before_request
def before():
    print("This is executed BEFORE each request.")


@app.get('/')
def index():
    return html


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return "do_the_login()"
    else:
        return "show_the_login_form()"


@app.route('/api/entities',
           methods=['GET', 'POST'])
def entities():
    if request.method == "GET":
        return {'message': 'This endpoint should return a list of entities',
                'method': request.method}

    elif request.method == "POST":
        return {'message': 'This endpoint should create an entity',
                'method': request.method,
                'args': request.args
                }


@app.route('/api/entities/<int:entity_id>',
           methods=['GET', 'PUT', 'DELETE'])
def entity(entity_id):
    if request.method == "GET":
        return {
            'id': entity_id,
            'message': 'This endpoint should return the entity {} details'.format(entity_id),
            'method': request.method
        }
    if request.method == "PUT":
        return {
            'id': entity_id,
            'message': 'This endpoint should update the entity {}'.format(entity_id),
            'method': request.method,
            'body': request.json
        }
    if request.method == "DELETE":
        return {
            'id': entity_id,
            'message': 'This endpoint should delete the entity {}'.format(entity_id),
            'method': request.method
        }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=52525, debug=True)
