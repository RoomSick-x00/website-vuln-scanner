from flask import Flask, render_template, request
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
    template_folder=os.path.join(BASE_DIR, "templates")
)

# fix cli import
sys.path.append(os.path.abspath(os.path.join(BASE_DIR, "..", "cli")))
import commands

@app.route("/debug-static")
def debug_static():
    import os
    path = os.path.join(BASE_DIR, "static", "css", "style.css")
    return f"Exists: {os.path.exists(path)} | Path: {path}"
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status/<scan_id>")
def api_status(scan_id):
    data = commands.get_status(scan_id)
    return data


@app.route("/submit", methods=["POST"])
def submit_scan():
    url = request.form["url"]

    response = commands.submit_scan(url)
    scan_id = response["id"]

    return render_template(
        "status.html",
        scan_id=scan_id,
        status=response["status"]
    )


@app.route("/status/<scan_id>")
def status(scan_id):
    response = commands.check_status(scan_id)

    return render_template(
        "status.html",
        scan_id=scan_id,
        status=response["status"]
    )


@app.route("/results/<scan_id>")
def results(scan_id):
    data = commands.get_results(scan_id)

    return render_template(
        "results.html",
        results=data.get("results", [])
    )

if __name__ == "__main__":
    app.run(debug=True)