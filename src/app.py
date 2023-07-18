from classes import Machine, User, Gym, Sesh, UserService
from flask import Flask, Response, render_template, session, request, redirect, flash
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required

# from psycopg2 import connect, DatabaseError

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
        user_service = UserService
        new_user = user_service.register_user(
            username=request.form.get("username"),
            email=request.form.get("email"),
            name=request.form.get("name"),
            date_of_birth=request.form.get("dob"),
            password=request.form.get("password"),
            languages=request.form.get("languages"),
        )

        for key, val in vars(new_user).items():
            if not val:
                if key == "date_of_birth":
                    flash(f'Please enter a {key.replace("_", " ")}')
                    return render_template("register.html")
                if key in ["friends", "usage", "hashed_password", "gym"]:
                    continue
                flash(f"Please enter a {key}")
                return render_template("register.html")

        confirmation = request.form.get("confirmation")

        if not confirmation:
            flash("Please confirm your password")
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

        # delete new_user variable from memory

        return redirect("/")


@app.route("/logout")
@login_required
def logout():
    session["user_id"] = None
    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
