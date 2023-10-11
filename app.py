import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///shiftplanner.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """homepage"""
    # This is an indendet block
    return render_template("index.html")

@app.route("/delshift", methods=["GET", "POST"])
def delshift():
    identifier = request.form.get("identifier")
    if identifier:
        db.execute("DELETE FROM shifts WHERE identifier=?", identifier)
    shifts = db.execute("SELECT * FROM shifts WHERE id=?", session["user_id"])
    return render_template("shifts.html", shifts = shifts)

    

@app.route("/shifts", methods=["GET", "POST"])
def shifts():
    """displays the shifts needed and allow to change them"""
    if request.method == "POST":
        daystart = request.form.get("daystart")
        timestart = request.form.get("timestart")
        dayend = request.form.get("dayend")
        timeend = request.form.get("timeend")
        db.execute(
        "INSERT INTO shifts (id, daystart, timestart, dayend, timeend) VALUES(?, ?, ?, ?, ?)",
        session["user_id"],
        daystart,
        timestart,
        dayend,
        timeend,
        )

    shifts = db.execute("SELECT * FROM shifts WHERE id=?", session["user_id"])
    return render_template("shifts.html", shifts = shifts)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")





@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        name = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("Failed to confirm password :(")
        if (
            len(name) != len(name.strip())
            or len(password) != len(password.strip())
            or name == ""
            or password == ""
        ):
            return apology("Pls don't leave any field blank!")

        hash_password = generate_password_hash(password)
        if db.execute("SELECT username FROM users WHERE username = ?", name):
            return apology("Username taken")
        else:
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)", name, hash_password
            )
            return redirect("/")

    else:
        return render_template("register.html")



