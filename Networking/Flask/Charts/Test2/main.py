# Importing required functions
import random

from flask import Flask
from bokeh.embed import components
from bokeh.plotting import figure

# Flask constructor
app = Flask(__name__)


# Root endpoint
@app.route('/')
def homepage():
    # Creating Plot Figure
    p = figure(height=350, sizing_mode="stretch_width")

    # Defining Plot to be a Scatter Plot
    p.circle(
        [i for i in range(10)],
        [random.randint(1, 50) for j in range(10)],
        size=20,
        color="navy",
        alpha=0.5
    )

    # Get Chart Components
    script, div = components(p)

    # Return the components to the HTML template
    return f'''
	<html lang="en">
		<head>
			<script src="https://cdn.bokeh.org/bokeh/release/bokeh-3.0.1.min.js"></script>
			<title>Bokeh Charts</title>
		</head>
		<body>
			<h1>Add Graphs to Flask apps using Python library - Bokeh</h1>
			{div}
			{script}
		</body>
	</html>
	'''


# Main Driver Function
if __name__ == '__main__':
    # Run the application on the local development server
    app.run(debug=True)
