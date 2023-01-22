from flask import Flask, request, flash, url_for, redirect, render_template
from backend.database import db
from model.Student import Student

flaskApp = Flask(__name__)
flaskApp.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/db_service_2.db'
flaskApp.config['SECRET_KEY'] = "random string"
flaskApp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


@flaskApp.route('/')
def index():
    students = Student.query.all()
    return render_template('index.html', students=students)


'''
For route '/<int:student_id>/
Use your browser to navigate to the URL for the second student:
http://127.0.0.1:5000/2
'''


@flaskApp.route('/<int:student_id>/')
def student(student_id):
    student = Student.query.get_or_404(student_id)
    return render_template('student.html', student=student)


@flaskApp.route('/create/', methods=('GET', 'POST'))
def create():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        age = int(request.form['age'])
        bio = request.form['bio']

        student = Student(firstname=firstname,
                          lastname=lastname,
                          email=email,
                          age=age,
                          bio=bio)

        db.session.add(student)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('create.html')


@flaskApp.route('/<int:student_id>/edit/', methods=('GET', 'POST'))
def edit(student_id):
    student = Student.query.get_or_404(student_id)

    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        age = int(request.form['age'])
        bio = request.form['bio']

        student.firstname = firstname
        student.lastname = lastname
        student.email = email
        student.age = age
        student.bio = bio

        db.session.add(student)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('edit.html', student=student)


@flaskApp.post('/<int:student_id>/delete/')
def delete(student_id):
    student = Student.query.get_or_404(student_id)
    db.session.delete(student)
    db.session.commit()
    return redirect(url_for('index'))




class Utils(object):

    @staticmethod
    def create_database():
        db.init_app(flaskApp)
        with flaskApp.app_context():
            db.create_all()

    @staticmethod
    def create_users():
        db.init_app(flaskApp)
        with flaskApp.app_context():
            john = Student(firstname='john', lastname='doe',
                           email='jd@example.com', age=23, bio='Biology student')

            sammy = Student(firstname='Sammy', lastname='Shark',
                            email='sammyshark@example.com', age=20, bio='Marine biology student')

            carl = Student(firstname='Carl', lastname='White',
                           email='carlwhite@example.com', age=22, bio='Marine geology student')

            db.session.add(john)
            db.session.add(sammy)
            db.session.add(carl)

            db.session.commit()

            print(john, " => ", john.id)
            print(sammy, " => ", sammy.id)
            print(carl, " => ", carl.id)


if __name__ == '__main__':
    # Utils.create_database()
    # Utils.create_users()

    # '''
    # Register app with database backend
    db.init_app(flaskApp)

    with flaskApp.app_context():
        flaskApp.run(debug=True)
    # '''