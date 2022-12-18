import json
import time

import pygal

from flask import Flask, render_template

app = Flask(__name__)

ABS_PATH: str = "/home/andtokm/DiskS/ProjectsUbuntu/Python/Networking/Flask_PyGal/Bar_1/"


@app.route("/")
def home():
    # return "Tutsplus : Welcome to PyGal Charting Library !! "
    with open(ABS_PATH + "/data/bar.json", 'r') as bar_file:
        data = json.load(bar_file)

    chart = pygal.Bar()
    mark_list = [x['mark'] for x in data]
    chart.add('Annual Mark List', mark_list)
    chart.x_labels = [x['year'] for x in data]
    chart.render_to_file('static/images/bar_chart.svg')
    img_url = 'static/images/bar_chart.svg?cache=' + str(time.time())
    return render_template('app.html', image_url=img_url)


if __name__ == "__main__":
    app.run()
