"""
Task 3 - Secure Coding Review (audit target)
A small Flask app that is INTENTIONALLY insecure, written for learning.
Never deploy this code.
"""
import hashlib
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "super-secret-123"          # hardcoded secret
DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()      # weak hash
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, pw_hash)
    row = get_db().cursor().execute(query).fetchone()          # SQL injection
    return "Welcome!" if row else "Invalid credentials"


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"                       # reflected XSS


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)   # command injection


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))            # code injection


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                     # insecure deserialization


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data, Loader=yaml.Loader))    # unsafe YAML


@app.route("/file")
def read_file():
    name = request.args.get("name", "")
    with open("uploads/" + name) as f:                          # path traversal
        return f.read()


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    return requests.get(url, verify=False).text                # SSRF, TLS off, no timeout


@app.route("/reset")
def reset():
    return str(random.randint(100000, 999999))                 # predictable token


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                        # debug mode on, all interfaces
