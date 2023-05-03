__author__ = 'Fahad Al Summan'

# created by fahad at 5:30 PM 2/20/23
import json

from flask import Flask, request,jsonify
app = Flask(__name__)

file = list()
@app.route("/api/add", methods=["POST"])
def api_add():
    req = request.json

    file.append(f"scanned : {jsonify(req).data}"
                f"\r\n")


    return""



@app.route("/")
def root():

 return "\r\n".join(file)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
