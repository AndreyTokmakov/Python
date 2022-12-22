from flask import Flask, Markup, render_template

app = Flask(__name__)


@app.route('/')
def line():
    legend = 'Monthly performance at 50m Freestyle'
    labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dic"]

    values = [26.94, 26.70, 26.80, 27.40, 26.45, 26.43, 26.30, 26.25, 26.20, 26.35, 26.00, 25.00]
    return render_template('line_chart.html', values=values, labels=labels, legend=legend)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
