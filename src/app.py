from classes import User, Gym, Sesh, UserService, GymService
from flask import Flask, Response, render_template, session, request, redirect, flash
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, fetch_row, fetch_rows, modify_rows
from psycopg2 import connect, DatabaseError
from re import fullmatch
from keys import HOST, USERNAME, PASSWORD, DBNAME, PORT
from datetime import datetime


app = Flask(__name__)

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


@app.route("/index")
@login_required
def index():
    username = "".join(
        fetch_row(
            """SELECT username FROM users WHERE user_id = %s""", (session["user_id"],)
        )
    )
    now = datetime.now()
    current_time = now.strftime("%H")
    current_time = int(current_time)
    if current_time < 12 and current_time > 5:
        time_response = "Good Morning,"
    elif current_time >= 12 and current_time < 17:
        time_response = "Good Afternoon,"
    else:
        time_response = "Good Evening,"
    return render_template("index.html", username=username, time_response=time_response)


@app.route("/index_gym")
@login_required
def index_gym():
    username = "".join(
        fetch_row(
            """SELECT gym_name FROM gym WHERE gym_id = %s""", (session["user_id"],)
        )
    )
    now = datetime.now()
    current_time = now.strftime("%H")
    current_time = int(current_time)
    if current_time < 12 and current_time > 5:
        time_response = "Good Morning,"
    elif current_time >= 12 and current_time < 17:
        time_response = "Good Afternoon,"
    else:
        time_response = "Good Evening,"
    return render_template(
        "index_gym.html", username=username, time_response=time_response
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    # maybe allow email address to be used to login too?
    elif request.method == "POST":
        session.clear()
        usermail, password = request.form.get("username"), request.form.get("password")
        if not usermail:
            flash("Please insert a username or email")
            return render_template("login.html")
        if not password:
            flash("Please insert a password")
            return render_template("login.html")

        if not (
            _ := fullmatch(
                r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
                usermail,
            )
        ):
            row = fetch_row(
                """SELECT * FROM users WHERE username = (%s)""", (usermail,)
            )
        else:
            row = fetch_row("""SELECT * FROM users WHERE email = (%s)""", (usermail,))

        # response = request.form["g-recaptcha-response"]
        # verify_response = requests.post(
        #     url=f"{VERIFY_URL}?secret={SECRET_KEY}&response={response}"
        # ).json()
        # if verify_response["success"] == False or verify_response["score"] < 0.5:
        #     flash("ReCaptcha failed!")
        #     return render_template("login.html", site_key=SITE_KEY)

        if not row:
            flash("No account found")
            return render_template("login.html")

        if len(row) != 7 or not check_password_hash(row[6], password):
            flash("Invalid username/email and/or password")
            # return render_template("login.html", site_key=SITE_KEY)
            return render_template("login.html")

        session["user_id"] = row[0]

        return redirect("/index")


@app.route("/login_gym", methods=["GET", "POST"])
def login_gym():
    if request.method == "GET":
        return render_template("login_gym.html")
    # maybe allow email address to be used to login too?
    elif request.method == "POST":
        session.clear()
        usermail, password = request.form.get("username"), request.form.get("password")
        if not usermail:
            flash("Please insert a username or email")
            return render_template("login.html")
        if not password:
            flash("Please insert a password")
            return render_template("login.html")

        if not (
            _ := fullmatch(
                r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
                usermail,
            )
        ):
            row = fetch_row(
                """SELECT * FROM gym WHERE contact_email = (%s)""", (usermail,)
            )
        else:
            row = fetch_row("""SELECT * FROM gym WHERE gym_name = (%s)""", (usermail,))

        # response = request.form["g-recaptcha-response"]
        # verify_response = requests.post(
        #     url=f"{VERIFY_URL}?secret={SECRET_KEY}&response={response}"
        # ).json()
        # if verify_response["success"] == False or verify_response["score"] < 0.5:
        #     flash("ReCaptcha failed!")
        #     return render_template("login.html", site_key=SITE_KEY)

        if not row:
            flash("No account found")
            return render_template("login_gym.html")

        if len(row) != 6 or not check_password_hash(row[5], password):
            flash("Invalid username/email and/or password")
            # return render_template("login.html", site_key=SITE_KEY)
            return render_template("login.html")

        session["user_id"] = row[0]

        return redirect("/index_gym")


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
            languages=request.form.getlist("languages"),
        )

        duplicate_check = fetch_row(
            """SELECT username FROM users WHERE username = %s""", (new_user.username,)
        )

        if duplicate_check:
            # if duplicate_check[0] == new_user.username:
            flash("Please choose a unique username")
            return render_template("register.html")

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

        if new_user.password != confirmation:
            flash("Please ensure passwords match")
            return render_template("register.html")

        new_user.hashed_password = generate_password_hash(
            new_user.password, method="pbkdf2:sha256", salt_length=8
        )

        now = datetime.now()
        current_time = now.strftime("%d/%m/%Y")

        modify_rows(
            """INSERT INTO users (username, email, name, date_of_birth, account_creation, hashed_password) VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                new_user.username,
                new_user.email,
                new_user.name,
                new_user.date_of_birth,
                current_time,
                new_user.hashed_password,
            ),
        )

        for language in new_user.languages:
            modify_rows(
                """INSERT INTO languages (user_id, language) VALUES (%s, %s)""",
                (language,),
            )

        del new_user

        return redirect("/")


@app.route("/register_gym", methods=["GET", "POST"])
def register_gym():
    if request.method == "GET":
        return render_template("register_gym.html")
    elif request.method == "POST":
        gym_service = GymService
        new_gym = gym_service.register_gym(
            name=request.form.get("gym_name"),
            address=request.form.get("address"),
            email=request.form.get("gym_email"),
        )

        duplicate_check = fetch_row(
            """SELECT username FROM users WHERE username = %s""", (new_gym.name,)
        )

        if duplicate_check:
            # if duplicate_check[0] == new_user.username:
            flash(
                "An account already exists with this name, please ensure you are not already signed up"
            )
            return render_template("register_gym.html")

        for key, val in vars(new_gym).items():
            if not val:
                if key not in ["hashed_password", "machines", "members", "repairing"]:
                    flash(f"Please enter a {key}")
                    return render_template("register.html")

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not confirmation:
            flash("Please confirm your password")
            return render_template("register.html")

        if password != confirmation:
            flash("Please ensure passwords match")
            return render_template("register.html")

        new_gym.hashed_password = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=8
        )

        now = datetime.now()
        current_time = now.strftime("%d/%m/%Y")

        modify_rows(
            """INSERT INTO gym (gym_name, contact_email, address, account_creation, hashed_password) VALUES (%s, %s, %s, %s, %s)""",
            (
                new_gym.name,
                new_gym.email,
                new_gym.address,
                current_time,
                new_gym.hashed_password,
            ),
        )

        del new_gym

        return redirect("/login")


@app.route("/profile_gym", methods=["GET"])
@login_required
def profile_gym():
    if request.method == "GET":
        return render_template("profile_gym.html")


@app.route("/gym_times", methods=["GET", "POST"])
@login_required
def gym_times():
    if request.method == "GET":
        return render_template("gym_times.html")
    if request.method == "POST":
        mon_open = request.form.get("monday_open")
        mon_close = request.form.get("monday_close")
        tues_open = request.form.get("tuesday_open")
        tues_close = request.form.get("tuesday_close")
        wed_open = request.form.get("wednesday_open")
        wed_close = request.form.get("wednesday_close")
        thurs_open = request.form.get("thursday_open")
        thurs_close = request.form.get("thursday_close")
        fri_open = request.form.get("friday_open")
        fri_close = request.form.get("friday_close")
        sat_open = request.form.get("saturday_open")
        sat_close = request.form.get("saturday_close")
        sun_open = request.form.get("sunday_open")
        sun_close = request.form.get("sunday_close")

        gym_service = GymService
        new_gym = gym_service.register_gym(name=session["user_id"])
        new_gym = gym_service.add_times(
            gym=new_gym,
            monday=f"{mon_open} - {mon_close}",
            tuesday=f"{tues_open} - {tues_close}",
            wednesday=f"{wed_open} - {wed_close}",
            thursday=f"{thurs_open} - {thurs_close}",
            friday=f"{fri_open} - {fri_close}",
            saturday=f"{sat_open} - {sat_close}",
            sunday=f"{sun_open} - {sun_close}",
        )

        modify_rows(
            """INSERT INTO opening_times (gym_id, monday, tuesday, wednesday, thursday, friday, saturday, sunday) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                new_gym.name,
                new_gym.opening_times["monday"],
                new_gym.opening_times["tuesday"],
                new_gym.opening_times["wednesday"],
                new_gym.opening_times["thursday"],
                new_gym.opening_times["friday"],
                new_gym.opening_times["saturday"],
                new_gym.opening_times["sunday"],
            ),
        )

        del new_gym
        return render_template("gym_times.html")


@app.route("/machines", methods=["GET", "POST"])
@login_required
def machines():
    if request.method == "GET":
        return render_template("machines.html")
    if request.method == "POST":
        gym_service = GymService
        new_gym = gym_service.register_gym(name=session["user_id"])
        try:
            machine, amount = request.form.get("machine"), int(
                request.form.get("amount")
            )
        except ValueError:
            flash("Please enter an integer")
            return render_template("machines.html")
        new_gym = gym_service.add_machines(
            gym=new_gym,
            machine=machine,
            amount=amount,
        )

        machine_id = fetch_row(
            """SELECT machine_id FROM machine WHERE name = %s""", (machine,)
        )

        dup_check = fetch_row(
            """SELECT amount FROM gym_machines WHERE gym_id = %s AND machine_id = %s""",
            (new_gym.name, machine_id),
        )

        if dup_check:
            old_amount = dup_check[0]
            new_amount = old_amount + amount
            modify_rows(
                """UPDATE gym_machines SET amount = %s WHERE gym_id = %s AND machine_id = %s""",
                (new_amount, new_gym.name, machine_id),
            )

        else:
            modify_rows(
                """INSERT INTO gym_machines (gym_id, machine_id, machine_name, amount) VALUES (%s, %s, %s, %s)""",
                (
                    new_gym.name,
                    machine_id,
                    machine,
                    new_gym.machines[machine],
                ),
            )

        current_machines = fetch_rows(
            """SELECT machine_name, amount FROM gym_machines WHERE gym_id = %s""",
            (new_gym.name,),
        )

        current_machines_rows = []

        for tup in current_machines:
            current_machines_rows.append({"Machine": tup[0].title(), "Amount": tup[1]})

        return render_template("machines.html", rows=current_machines_rows)


@app.route("/logout")
@login_required
def logout():
    session["user_id"] = None
    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
