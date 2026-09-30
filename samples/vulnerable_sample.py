"""
Sample Flask app with intentionally introduced vulnerabilities, used only
as demo input for the Secure Code Review tool. Do not deploy.
"""

import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)

DB_PASSWORD = "sup3rSecretPassword!"
API_KEY = "sk_live_51Hh2f9K3jY8m2LqW"


def get_user(conn, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def run_backup(filename):
    os.system("tar -czf backup.tar.gz " + filename)


def restore_session(blob):
    return pickle.loads(blob)


def load_config(path):
    with open(path) as f:
        return yaml.load(f)


def check_health(url):
    return requests.get(url, verify=False)


def generate_session_token():
    import random
    return str(random.random())


@app.route("/go")
def go():
    target = request.args.get("next")
    return redirect(target)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)


def check_permission(user):
    assert user.is_admin, "not authorized"


def fetch_data():
    try:
        return requests.get("https://internal.example/data").json()
    except Exception:
        pass


def clear_temp_files():
    try:
        os.remove("/tmp/upload.tmp")
    except:
        pass


def set_session_cookie(response, session_id):
    response.set_cookie("session", session_id)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
