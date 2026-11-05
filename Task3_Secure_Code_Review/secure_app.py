"""
Task 3 - Secure Coding Review (remediated version)
Same features as vulnerable_app.py, with each finding fixed.
"""
import ast
import json
import operator
import os
import re
import secrets
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, request, send_from_directory
from markupsafe import escape
from werkzeug.security import check_password_hash

app = Flask(__name__)
SECRET_KEY = os.environ.get("APP_SECRET_KEY")      # from environment, never in code
DB_PATH = "users.db"
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
ALLOWED_FETCH_HOSTS = {"example.com", "api.example.com"}


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    row = get_db().execute(
        "SELECT password FROM users WHERE username = ?", (username,)).fetchone()   # parameterized
    if row and check_password_hash(row[0], password):                              # salted hash
        return "Welcome!"
    return "Invalid credentials", 401


@app.route("/hello")
def hello():
    return "<h1>Hello " + str(escape(request.args.get("name", ""))) + "</h1>"      # output escaping


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True,
                         text=True, timeout=5, check=False)                         # no shell
    return out.stdout


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}


def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    try:
        return str(_safe_eval(ast.parse(request.args.get("expr", "0"), mode="eval")))
    except (ValueError, SyntaxError, ZeroDivisionError):
        abort(400)


@app.route("/load", methods=["POST"])
def load():
    try:
        return str(json.loads(request.data))                                        # JSON, not pickle
    except ValueError:
        abort(400)


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.safe_load(request.data))                                        # safe_load


@app.route("/file")
def read_file():
    return send_from_directory(UPLOAD_DIR, request.args.get("name", ""))           # blocks ../


@app.route("/fetch")
def fetch():
    url = urlparse(request.args.get("url", ""))
    if url.scheme != "https" or url.hostname not in ALLOWED_FETCH_HOSTS:           # allow-list
        abort(400)
    return requests.get(url.geturl(), timeout=5).text                               # TLS on, timeout


@app.route("/reset")
def reset():
    return secrets.token_urlsafe(32)                                                # CSPRNG


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
