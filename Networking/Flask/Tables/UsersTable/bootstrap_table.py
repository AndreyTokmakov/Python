from flask import Flask, render_template

from database import app, db
from User import User


@app.route('/')
def index():
    users = User.query
    return render_template('bootstrap_table.html', title='Bootstrap Table',
                           users=users)


# TODO: call create_users.py
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
