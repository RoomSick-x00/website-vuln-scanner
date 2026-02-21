from flask import Flask, render_template, request
import sys
import os

# Add cli folder to path
sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', 'cli')
    )
)

import commands

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/submit", methods=["POST"])
def submit_scan():

    url = request.form["url"]

    result = commands.submit_scan(url)

    scan_id = result["scan_id"]

    return render_template("status.html", scan_id=scan_id)


@app.route("/results/<scan_id>")
def show_results(scan_id):

    result = commands.get_results(scan_id)

    return render_template(
        "results.html",
        scan_id=result["scan_id"],
        results=result["results"]
    )


if __name__ == "__main__":
    app.run(debug=True)
