import datetime

from flask import Flask
from flask import render_template

app = Flask(__name__)


@app.route("/")
def time_chart():
    legend = 'TCP total'
    temperatures = [33.7, 39.4, 43.8, 47.8, 52.7, 57.2,
                    61.8, 64.7, 65.2, 65.0, 63.5, 60.7,
                    57.2, 52.4, 47.2, 43.9, 39.3, 33.1]

    times = [datetime.datetime(year=2022, month=1, day=31, hour=11, minute=14, second=15),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=14, second=30),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=14, second=45),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=00),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=15),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=30),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=45),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=00),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=15),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=30),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=45),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=00),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=15),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=30),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=45),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=18, second=00),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=18, second=15),
             datetime.datetime(year=2022, month=1, day=31, hour=11, minute=18, second=32)]

    tcp_legend = 'TCP packets'
    tcp_value = [73.7, 73.4, 73.8, 72.8, 68.7, 65.2,
                 61.8, 58.7, 58.2, 58.3, 60.5, 65.7,
                 70.2, 71.4, 71.2, 70.9, 71.3, 71.1]

    timestamps = [datetime.datetime(year=2022, month=1, day=31, hour=11, minute=14, second=15),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=14, second=30),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=14, second=45),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=00),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=15),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=30),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=15, second=45),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=00),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=15),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=30),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=16, second=45),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=00),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=15),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=30),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=17, second=45),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=18, second=00),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=18, second=15),
                  datetime.datetime(year=2022, month=1, day=31, hour=11, minute=18, second=32)]

    return render_template('time_chart.html',
                           values=temperatures,
                           labels=times,
                           legend=legend)


if __name__ == "__main__":
    app.run(debug=True)
