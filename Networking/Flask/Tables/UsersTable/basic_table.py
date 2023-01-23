from flask import render_template

from database import app, db
from User import User


@app.route('/')
def index():
    users = User.query
    return render_template('basic_table.html', title='Basic Table',
                           users=users)


# TODO: call create_users.py
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
