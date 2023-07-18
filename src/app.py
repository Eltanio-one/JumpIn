from classes import Machine, User, Gym, Sesh
from flask import Flask, Response, render_template, session, request, redirect, flash
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, modify_rows
from psycopg2 import connect, DatabaseError

app = Flask(__name__)

# configure flask-session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    # HTTP/1.0 implmentation of cache-control
    # response.headers["Pragma"] = "no-cache"
    # return the response
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    elif request.method == "POST":
        new_user = User(
            username=request.form.get("username"),
            password=request.form.get("password"),
            name=request.form.get("name"),
            dob=request.form.get("dob"),
            languages=request.form.get("languages"),
        )
        confirmation = (request.form.get("confirmation"),)

        if not new_user.username:
            flash("Please enter a username")
            return render_template("register.html")

        if not new_user.password:
            flash("Please enter a password")
            return render_template("register.html")

        if not confirmation:
            flash("Please confirm your password")
            return render_template("register.html")

        if not new_user.name:
            flash("Please enter your name")
            return render_template("register.html")

        if not new_user.dob:
            flash("Please enter your date of birth")
            return render_template("register.html")

        if not new_user.languages:
            flash("Please enter at least one language")
            return render_template("register.html")
        # conn = None
        # try:
        #     conn = connect(
        #         host="host.docker.internal",
        #         user="postgres",
        #         password="postgres",
        #         dbname="to-do",
        #         port=5432,
        #     )
        #     with conn:
        #         with conn.cursor() as cur:
        #             cur.execute(
        #                 """SELECT username FROM users WHERE username = %s""",
        #                 (username,),
        #             )
        #             dup = cur.fetchone()
        #             if dup:
        #                 if dup[0] == username:
        #                     flash("Please choose a unique username")
        #                     return render_template("register.html")
        # except (Exception, DatabaseError) as error:
        #     print(error)

        if new_user.password != confirmation:
            flash("Please ensure passwords match")
            return render_template("register.html")

        new_user.hashed_password = generate_password_hash(
            new_user.password, method="pbkdf2:sha256", salt_length=8
        )

        # modify_rows(
        #     """INSERT INTO users (username, hash) VALUES (%s, %s)""", (username, hash)
        # )

        return redirect("/")


@app.route("/logout")
@login_required
def logout():
    session["user_id"] = None
    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
