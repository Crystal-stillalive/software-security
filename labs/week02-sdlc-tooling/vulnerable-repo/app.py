"""
Deliberately INSECURE sample for Week 2 scanning practice.
Do NOT copy these patterns into real code. Find them with SAST + secret scanning.
 
--- FIXED (Task 8) ---
"""
import os
import sqlite3
import subprocess
from argon2 import PasswordHasher
from flask import Flask, request
 
app = Flask(__name__)
ph = PasswordHasher()
 
# FIX (CWE-798): secrets loaded from environment, never hardcoded in source.
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
 
 
@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # FIX (CWE-89): parameterized query — user input is bound as data,
    # never concatenated/formatted into the SQL string itself.
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())
 
 
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (CWE-78): shell=True removed; command passed as an argument list
    # so the OS never invokes a shell that could interpret metacharacters
    # (;, |, &&, etc.) in user-controlled input.
    return subprocess.check_output(["ping", "-c", "1", host])
 
 
def store_password(pw):
    # FIX (CWE-327): argon2id — slow, memory-hard, auto-salted KDF,
    # replacing the fast, unsalted MD5 hash.
    return ph.hash(pw)
 
 
if __name__ == "__main__":
    # FIX (CWE-489): debug mode disabled.
    app.run(debug=False)
 
