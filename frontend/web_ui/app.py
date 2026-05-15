from flask import Flask, render_template, request, make_response
import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
    template_folder=os.path.join(BASE_DIR, "templates")
)
sys.path.append(os.path.abspath(os.path.join(BASE_DIR, "..", "cli")))
import commands_cli as commands

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
    result = commands.submit_scan(url)
    if "error" in result:
        return result["error"]
    if "id" not in result:
        return f"Backend response: {result}"
    scan_id = result["id"]
    return render_template("status.html", scan_id=scan_id)

@app.route("/status/<scan_id>")
def status(scan_id):
    response = commands.check_status(scan_id)
    return render_template("status.html", scan_id=scan_id, status=response["status"])

@app.route("/results/<scan_id>")
def results(scan_id):
    data = commands.get_results(scan_id)
    return render_template(
        "results.html",
        results=data.get("results", [])
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)