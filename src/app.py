from flask import Flask, session, render_template, request, redirect
import sqlite3
import argon2
import sys
from datetime import timedelta

# setup

app = Flask(__name__)
app.secret_key = b'\x9f\xbe\xd0\x96\xc2\xc8\x18\xa4bG\xa8\xab\xb3\x85)\xea\x88u\xf1Y\xf8\x18\x14\xbd'
app.permanent_session_lifetime = timedelta(minutes=5) # this is very short for the sake of testing

hasher = argon2.PasswordHasher()

def executeSQL(statement, values=()):
    con = sqlite3.connect("accounts.db")
    cur = con.cursor()
    cur.execute(statement, values)
    result = cur.fetchall()
    con.commit()
    cur.close()
    con.close()
    return result

def checkSchema():
    with open("src/schema.sql", "r") as f:
        executeSQL(f.read())

    schema = executeSQL("PRAGMA table_info('account');")
    if schema != [(0, 'email', 'VARCHAR(250)', 1, None, 1), (1, 'password', 'VARCHAR(250)', 1, None, 0)]:
        app.logger.error("Schema mismatch!  Either update this server to match the schema.sql file, or modify the database to bring it inline with the current server version")
        app.logger.error(schema)
        sys.exit(1)
    else:
        app.logger.info("Schema check OK")

checkSchema()
# front end

@app.get("/")
def hello():
    try:
        name = session['email']
    except KeyError:
        name = "anonymous"
    return render_template("index.html", user_string=name)

@app.get("/logon")
def logonPage():
    if "email" in session:
        return redirect("/")
    return render_template("logon.html")

@app.get("/register")
def registerPage():
    return render_template("register.html")


# back end

@app.post("/logon")
def logon():
    # check both email and password fields exist
    try:
        email = request.form["email"]
        attemptedPassword = request.form["password"]
    except KeyError:
        return "missing form keys email/password", 400

    try:
        correctPassHash = executeSQL("SELECT password FROM account WHERE email = ?", (email,))[0][0]
    except IndexError:
        correctPassHash = "" # email does not exist, but attempt to verify the password still to prevent timing attacks

    passwordMatch = False
    try:
        hasher.verify(correctPassHash, attemptedPassword)
        passwordMatch = True
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHashError):
        passwordMatch = False # password does not match, or the email does not match and the correct hash was set to ""

    if passwordMatch:
        session['email'] = email
        return redirect("/")
    else:
        return redirect("/logon")

@app.get("/logoff")
def logoff():
    session.clear()
    if request.referrer is None:
        return redirect("/")
    else:
        return redirect(request.referrer)


@app.post("/register")
def register():
    try:
        email = request.form["email"]
        password = request.form["password"]
    except KeyError:
        return "missing form keys email/password", 400

    passwordHash = hasher.hash(password)
    try:
        executeSQL("INSERT INTO account (email, password) VALUES (?,?);", (email, passwordHash))
    except sqlite3.IntegrityError:
        return redirect("/register")
    return redirect("/")
