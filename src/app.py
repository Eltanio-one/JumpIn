from classes import UserService, GymService
from flask import Flask, render_template, session, request, redirect, flash, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import (
    login_required,
    gym_only,
    fetch_row,
    fetch_rows,
    fetch_dict,
    modify_rows,
    verify_password,
    verify_email,
    matching_algorithm,
    machine_matches,
    get_time,
    check_hour,
    generate_unique_code,
)
import sys
import os
import random
from flask_socketio import SocketIO, join_room, leave_room, send
from string import ascii_uppercase

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
socketio = SocketIO(app)

rooms = {}


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
    time_response = check_hour()
    return render_template(
        "index.html", username=session["user"].username, time_response=time_response
    )


@app.route("/index_gym")
@login_required
@gym_only
def index_gym():
    time_response = check_hour()
    return render_template(
        "index_gym.html", username=session["user"].username, time_response=time_response
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        session.clear()
        usermail, password = request.form.get("username"), request.form.get("password")
        if not usermail:
            flash("Please insert a username or email")
            return redirect("/login")
        if not password:
            flash("Please insert a password")
            return redirect("/login")

        if not verify_email(usermail):
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
            return redirect("/login")

        if len(row) != 8 or not check_password_hash(row[6], password):
            flash("Invalid username/email and/or password")
            # return render_template("login.html", site_key=SITE_KEY)
            return redirect("/login")

        user_service = UserService
        new_user = user_service.register_user(
            username=row[1],
            email=row[2],
            name=row[3],
            date_of_birth=row[4],
            account_creation=row[5],
            hashed_password=row[6],
        )

        session["user"] = new_user
        session["user_id"] = row[0]

        return redirect("/index")


@app.route("/login_gym", methods=["GET", "POST"])
def login_gym():
    if request.method == "GET":
        return render_template("login_gym.html")
    elif request.method == "POST":
        session.clear()
        usermail, password = request.form.get("username"), request.form.get("password")
        if not usermail:
            flash("Please insert a username or email")
            return redirect("/login")
        if not password:
            flash("Please insert a password")
            return redirect("/login")

        if not verify_email(usermail):
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
            return redirect("/login")

        if len(row) != 6 or not check_password_hash(row[5], password):
            flash("Invalid username/email and/or password")
            # return render_template("login.html", site_key=SITE_KEY)
            return redirect("/login")

        gym_service = GymService
        new_gym = gym_service.register_gym(
            username=row[1],
            email=row[2],
            address=row[3],
            account_creation=row[4],
            hashed_password=row[5],
        )

        session["user_id"] = row[0]
        session["username"] = new_gym.username
        session["user"] = new_gym

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
            flash("Please choose a unique username")
            return redirect("/register")

        for key, val in vars(new_user).items():
            if not val:
                if key == "date_of_birth":
                    flash(f'Please enter a {key.replace("_", " ")}')
                    return redirect("/register")
                if key in ["friends", "usage", "hashed_password", "gym"]:
                    continue
                flash(f"Please enter a {key}")
                return redirect("/register")

        if not verify_email(new_user.email):
            flash("Please enter a valid email address")
            return redirect("/register")

        if not verify_password(new_user.password):
            flash("Please enter a password that meets the password requirements")
            return redirect("/register")

        confirmation = request.form.get("confirmation")

        if not confirmation:
            flash("Please confirm your password")
            return redirect("/register")

        if new_user.password != confirmation:
            flash("Please ensure passwords match")
            return redirect("/register")

        new_user.hashed_password = generate_password_hash(
            new_user.password, method="pbkdf2:sha256", salt_length=8
        )

        modify_rows(
            """INSERT INTO users (username, email, name, date_of_birth, account_creation, hashed_password) VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                new_user.username,
                new_user.email,
                new_user.name,
                new_user.date_of_birth,
                get_time(),
                new_user.hashed_password,
            ),
        )

        for language in new_user.languages:
            modify_rows(
                """INSERT INTO languages (user_id, language) VALUES (%s, %s)""",
                (session["user_id"], language),
            )

        del new_user

        return redirect("/login")


@app.route("/cancel_request", methods=["POST"])
@login_required
def cancel_request():
    matchee = request.form.get("username")
    matchee_id = fetch_row(
        """SELECT user_id FROM users WHERE username = %s""", (matchee,)
    )[0]
    modify_rows(
        """DELETE FROM requested_sessions WHERE user_id = %s AND matchee_id = %s""",
        (session["user_id"], matchee_id),
    )
    return redirect("/session_requests")


@app.route("/decline_request", methods=["POST"])
@login_required
def decline_request():
    matcher = request.form.get("username")
    matcher_id = fetch_row(
        """SELECT user_id FROM users WHERE username = %s""", (matcher,)
    )

    modify_rows(
        """UPDATE requested_sessions SET declined = true WHERE user_id = %s AND matchee_id = %s""",
        (matcher_id, session["user_id"]),
    )
    return redirect("/session_requests")


@app.route("/accept_request", methods=["POST"])
@login_required
def accept_request():
    matcher = request.form.get("username")
    matcher_id = fetch_row(
        """SELECT user_id FROM users WHERE username = %s""", (matcher,)
    )

    modify_rows(
        """UPDATE requested_sessions SET accepted = true WHERE user_id = %s AND matchee_id = %s""",
        (matcher_id, session["user_id"]),
    )
    return redirect("/session_requests")


@app.route("/session_requests", methods=["GET"])
@login_required
def session_requests():
    if request.method == "GET":
        # first get requested sessions
        your_requests = fetch_rows(
            """SELECT * FROM requested_sessions WHERE user_id = %s""",
            (session["user_id"],),
        )
        # for your requests, make a dict of matchee name and machines matched
        your_requests_output, others_requests_output = {}, {}
        for row in your_requests:
            username = fetch_row(
                """SELECT username FROM users WHERE user_id = %s""", (row[2],)
            )[0]
            your_requests_output[username] = row[3]
        others_requests = fetch_rows(
            """SELECT * FROM requested_sessions WHERE accepted = false AND declined = false AND matchee_id = %s""",
            (session["user_id"],),
        )

        for row in others_requests:
            username = fetch_row(
                """SELECT username FROM users WHERE user_id = %s""", (row[1],)
            )[0]
            others_requests_output[username] = row[3]

        # need a notifications table that shows accepted/declined!
        notifications = fetch_rows(
            """SELECT * FROM requested_sessions WHERE accepted = true OR declined = true"""
        )
        notifications_output = {}
        if not notifications:
            notifications = ""
        else:
            results = fetch_dict(
                """SELECT * FROM requested_sessions WHERE accepted = true OR declined = true"""
            )[0]
            username = fetch_row(
                """SELECT username FROM users WHERE user_id = %s""",
                (results["matchee_id"],),
            )[0]
            for key, value in results.items():
                if value == True:
                    notifications_output[username] = key

        others_requests_output["bob"] = ["chest press"]
        return render_template(
            "session_requests.html",
            your_requests=your_requests_output,
            others_requests=others_requests_output,
            notifications=notifications_output,
        )


@app.route("/complete_session", methods=["POST"])
@login_required
def complete_session():
    username = request.form.get("username")
    decision = request.form.get("decision")
    matchee_id = fetch_row(
        """SELECT user_id FROM users WHERE username = %s""", (username,)
    )[0]
    req_session = fetch_row(
        """SELECT * FROM requested_sessions WHERE user_id = %s AND matchee_id = %s""",
        (session["user_id"], matchee_id),
    )
    print(req_session)
    # if decision == "accepted":
    # modify_rows(
    #     """INSERT INTO archived_sessions (user_id, matchee_id, machines, gym_id, booking_date) VALUES (%s, %s, %s, %s, %s)""",
    #     (
    #         req_session[1],
    #         req_session[2],
    #         req_session[3],
    #         req_session[4],
    #         get_time(),
    #     ),
    # )
    modify_rows(
        """DELETE FROM requested_sessions WHERE user_id = %s AND matchee_id = %s""",
        (session["user_id"], matchee_id),
    )

    return redirect("/session_requests")


@app.route("/propose_session", methods=["GET", "POST"])
@login_required
def propose_session():
    if request.method == "POST":
        matchee = request.form.get("chosen_user")

        # add the selected session request to a different table
        # this means collect the db entry between matcher and matchee
        # and transfer to requested sessions table
        matchee_id = fetch_row(
            """SELECT user_id FROM users WHERE username = %s""", ("t",)
        )[0]

        requested_match = fetch_row(
            """SELECT * FROM potential_matches WHERE user_id = %s AND matchee_id = %s""",
            (session["user_id"], matchee_id),
        )

        # modify_rows(
        #     """INSERT INTO requested_sessions (user_id, matchee_id, machines, gym_id) VALUES (%s, %s, %s, %s)""",
        #     (
        #         requested_match[1],
        #         requested_match[2],
        #         requested_match[3],
        #         requested_match[4],
        #     ),
        # )

        modify_rows(
            """INSERT INTO requested_sessions (user_id, matchee_id, machines, gym_id) VALUES (%s, %s, %s, %s)""",
            (
                session["user_id"],
                1,
                ["chest press"],
                1,
            ),
        )
        # remove all potential matches linked to the matcher from potentials
        modify_rows(
            """DELETE FROM potential_matches WHERE user_id = %s""",
            (session["user_id"],),
        )

        # return render_template() for a page which will show your requests and peoples requests to you?
        return redirect("/session_requests")


@app.route("/session_plan", methods=["GET", "POST"])
@login_required
def session_plan():
    if request.method == "GET":
        if not (
            gym_id := fetch_row(
                """SELECT gym_id FROM users WHERE user_id = %s""", (session["user_id"],)
            )
        ):
            flash(
                "Please register for a gym on your profile page before creating a session"
            )
            rows, available_machines, user_matches = {"": ""}, [""], {"": ""}

            return render_template(
                "session_plan.html",
                rows=rows,
                available_machines=available_machines,
                user_matches=user_matches,
            )

        available_machines = fetch_rows(
            """SELECT machine_name FROM gym_machines WHERE gym_id = %s""",
            (gym_id,),
        )
        rows, user_matches = {"": ""}, {"": ""}
        return render_template(
            "session_plan.html",
            rows=rows,
            available_machines=available_machines,
            user_matches=user_matches,
        )
    elif request.method == "POST":
        if not (
            gym_id := fetch_row(
                """SELECT gym_id FROM users WHERE user_id = %s""", (session["user_id"],)
            )
        ):
            flash(
                "Please register for a gym on your profile page before creating a session"
            )
            rows, available_machines = {"": ""}, [""]

            return render_template("session_plan.html", rows=rows)
        machine_list = [
            request.form.get("machine1"),
            request.form.get("machine2"),
            request.form.get("machine3"),
            request.form.get("machine4"),
            request.form.get("machine5"),
        ]

        prev_session = fetch_row(
            """SELECT * FROM user_session WHERE user_id = %s""",
            (session["user_id"],),
        )
        # if prev_session:
        #     flash(
        #         "Please cancel your previous session request before submitting another!"
        #     )
        #     return redirect("/session_plan")

        modify_rows(
            """INSERT INTO user_session (user_id, user_name, request_time, machine_list) VALUES (%s, %s, %s, %s)""",
            (
                session["user_id"],
                session["user"].username,
                datetime.now(),
                machine_list,
            ),
        )
        rows = fetch_rows(
            """SELECT user_id, machine_list, user_name FROM user_session ORDER BY request_time LIMIT 5"""
        )
        rows = [
            (
                1,
                [
                    "chest press",
                    "chest press",
                    "chest press",
                    "chest press",
                    "chest press",
                ],
                "paulie",
            ),
            (
                2,
                [
                    "decline bench",
                    "decline bench",
                    "arm curl bench",
                    "olympic weight bench",
                    "incline bench",
                ],
                "warren",
            ),
            (
                3,
                [
                    "ligma press",
                    "chest press",
                    "chest press",
                    "chest press",
                    "chest press",
                ],
                "char",
            ),
            (
                4,
                [
                    "chest press",
                    "ligma press",
                    "chest press",
                    "chest press",
                    "chest press",
                ],
                "ligma",
            ),
            (
                5,
                [
                    "ligma press",
                    "ligma press",
                    "ligma press",
                    "ligma press",
                    "ligma press",
                ],
                "sugma",
            ),
        ]
        if len(rows) < 2:
            flash(
                "Please wait whilst we fill the lobby and attempt to find you a match, or cancel your request below!"
            )
            return redirect("/session_plan")
        else:
            """Algorithm to link lobby members to their closest matched routine member"""
            matches_output = matching_algorithm(rows)
            user_matches = machine_matches(session["user_id"], rows)

            """could add all potential matches to user_matches table, then when the user chooses we eliminate all that were not between them"""
            for user, machines in user_matches.items():
                matchee_id = fetch_row(
                    """SELECT user_id FROM users WHERE username = %s""", (user,)
                )
                modify_rows(
                    """INSERT INTO potential_matches (user_id, matchee_id, machines, gym_id) VALUES (%s, %s, %s, %s)""",
                    (session["user_id"], matchee_id, machines, gym_id),
                )

            """Add the machines that are provided to each users usage db"""
            for machine in machine_list:
                machine_id = fetch_row(
                    """SELECT machine_id FROM machine WHERE name = %s""", (machine,)
                )
                check = fetch_row(
                    """SELECT uses FROM usage WHERE user_id = %s AND machine_id = %s""",
                    (session["user_id"], machine_id),
                )
                if not check:
                    modify_rows(
                        """INSERT INTO usage (user_id, machine_id, machine_name, uses) VALUES (%s, %s, %s, %s)""",
                        (session["user_id"], machine_id, machine, 1),
                    )
                else:
                    modify_rows(
                        """UPDATE usage SET uses = uses + 1 WHERE user_id = %s AND machine_id = %s""",
                        (session["user_id"], machine_id),
                    )

            return render_template(
                "propose_session.html",
                rows=matches_output,
                user_matches=user_matches,
            )


@app.route("/favourite_gym", methods=["POST"])
@login_required
def favourite_gym():
    if request.method == "POST":
        favourite_gym = request.form.get("favourite_gyms")

        gym_id = fetch_row(
            """SELECT gym_id FROM gym WHERE gym_name = %s""", (favourite_gym,)
        )

        session["user"].gym_id = gym_id

        reg_check = fetch_row(
            """SELECT * FROM members WHERE user_id = %s""", (session["user_id"],)
        )

        if reg_check:
            modify_rows(
                """UPDATE members SET gym_id = %s WHERE user_id = %s""",
                (
                    gym_id,
                    session["user_id"],
                ),
            )
        else:
            modify_rows(
                """INSERT INTO members (gym_id, user_id) VALUES (%s, %s)""",
                (gym_id, session["user_id"]),
            )

        modify_rows(
            """UPDATE users SET gym_id = %s WHERE user_id = %s""",
            (
                gym_id,
                session["user_id"],
            ),
        )

        return redirect("/user_profile")


@app.route("/delete_user", methods=["GET", "POST"])
@login_required
def delete_user():
    if request.method == "GET":
        return render_template("delete_user.html")
    elif request.method == "POST":
        password = request.form.get("password_delete")
        if not check_password_hash(session["user"].hashed_password, password):
            flash("Incorrect password provided")
            return redirect("/delete_user")

        modify_rows("""DELETE FROM users WHERE user_id = %s""", (session["user_id"],))

        session["user"] = None

    return redirect("/logout")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")
    elif request.method == "POST":
        old_password, new_password, confirmation = (
            request.form.get("password_old"),
            request.form.get("password_new"),
            request.form.get("confirmation"),
        )
        if not old_password:
            flash("Please enter your old password")
            return redirect("/change_password")
        if not new_password:
            flash("Please enter your new password")
            return redirect("/change_password")
        if not confirmation:
            flash("Please confirm your password")
            return redirect("/change_password")

        if not check_password_hash(session["user"].hashed_password, old_password):
            flash("Incorrect password provided")
            return redirect("/change_password")

        if not verify_password(new_password):
            flash("Please enter a password that meets the password requirements")
            return redirect("/change_password")

        if new_password != old_password:
            flash("Please choose a new password")
            return redirect("/change_password")

        if new_password != confirmation:
            flash("Confirmation should match new password")
            return redirect("/change_password")

        hashed_password = generate_password_hash(
            new_password, method="pbkdf2:sha256", salt_length=8
        )

        session["user"].hashed_password = hashed_password

        modify_rows(
            """UPDATE users SET hashed_password = %s WHERE user_id = %s""",
            (hashed_password, session["user_id"]),
        )
    flash("Please log in again using your new password")
    return redirect("/logout")


@app.route("/chatroom", methods=["POST", "GET"])
@login_required
def chatroom():
    if request.method == "GET":
        return render_template("chatroom.html")
    if request.method == "POST":
        session["room"] = None
        username = request.form.get("username")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not username:
            flash("Please enter your username")
            return render_template("chatroom.html", code=code, username=username)

        if join != False and not code:
            flash("Please enter a room code")
            return render_template("chatroom.html", code=code, username=username)

        room = code
        if create != False:
            room = generate_unique_code(4, rooms)
            rooms[room] = {"members": 0, "messages": []}
        elif code not in rooms:
            flash("Room doesn't exist")
            return render_template("chatroom.html", code=code, username=username)

        session["room"] = room
        return redirect(url_for("room", code=code))


@app.route("/room/<code>")
@login_required
def room(code):
    room = session["room"]
    if not room or not session["user_id"] or room not in rooms:
        return redirect("/index")
    return render_template("room.html", code=code)


@socketio.on("connect")
def connect(auth):
    room = session["room"]
    username = session["user"].username
    if not room or not username:
        return
    if room not in rooms:
        leave_room(room)
        return
    join_room(room)
    send({"username": username, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{username} joined room {room}")


@app.route("/user_profile")
@login_required
def user_profile():
    top_machines = fetch_rows(
        """SELECT machine_name FROM usage WHERE user_id = %s LIMIT 5""",
        (session["user_id"],),
    )

    gyms = fetch_rows("""SELECT gym_name FROM gym ORDER BY gym_id ASC""")

    available_machines = fetch_rows(
        """SELECT machine_name FROM gym_machines WHERE gym_id = %s""",
        (session["user"].gym_id,),
    )

    account_info = fetch_row(
        """SELECT username, email, name, account_creation FROM users WHERE user_id = %s""",
        (session["user_id"],),
    )

    gym_name = fetch_row(
        """SELECT gym_name FROM gym WHERE gym_id = %s""", (session["user"].gym_id,)
    )

    dict_labels = ["Username:", "Email:", "Name:", "Member since:"]

    details_dict = dict(zip(dict_labels, account_info))

    if not gym_name:
        details_dict[
            "Your current gym:"
        ] = "Not current registered with a gym, do so above!"

    else:
        details_dict["Your current gym:"] = gym_name[0]

    if not top_machines:
        top_machines = [""]

    return render_template(
        "user_profile.html",
        rows=top_machines,
        gyms=gyms,
        available_machines=available_machines,
        account_details=details_dict,
    )


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
            """SELECT username FROM users WHERE username = %s""", (new_gym.username,)
        )

        if duplicate_check:
            flash(
                "An account already exists with this name, please ensure you are not already signed up"
            )
            return render_template("register_gym.html")

        for key, val in vars(new_gym).items():
            if not val:
                if key not in ["hashed_password", "machines", "members", "repairing"]:
                    flash(f"Please enter a {key}")
                    return render_template("register.html")

        if not verify_email(new_gym.email):
            flash("Please enter a valid email address")
            return redirect("/register_gym")

        if not verify_password(new_gym.password):
            flash("Please enter a password that meets the password requirements")
            return redirect("/register")

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

        modify_rows(
            """INSERT INTO gym (gym_name, contact_email, address, account_creation, hashed_password) VALUES (%s, %s, %s, %s, %s)""",
            (
                new_gym.username,
                new_gym.email,
                new_gym.address,
                get_time(),
                new_gym.hashed_password,
            ),
        )

        return redirect("/login")


@app.route("/profile_gym", methods=["GET"])
@login_required
@gym_only
def profile_gym():
    if request.method == "GET":
        return render_template("profile_gym.html")


@app.route("/gym_times", methods=["GET", "POST"])
@login_required
@gym_only
def gym_times():
    if request.method == "GET":
        return render_template("gym_times.html")
    if request.method == "POST":
        gym_service = GymService
        new_gym = session["user"]
        new_gym = gym_service.add_times(
            gym=new_gym,
            monday=f'{request.form.get("monday_open")} - {request.form.get("monday_close")}',
            tuesday=f'{request.form.get("tuesday_open")} - {request.form.get("tuesday_close")}',
            wednesday=f'{request.form.get("wednesday_open")} - {request.form.get("wednesday_close")}',
            thursday=f'{request.form.get("thursday_open")} - {request.form.get("thursday_close")}',
            friday=f'{request.form.get("friday_open")} - {request.form.get("friday_close")}',
            saturday=f'{request.form.get("saturday_open")} - {request.form.get("saturday_close")}',
            sunday=f'{request.form.get("sunday_open")} - {request.form.get("sunday_close")}',
        )

        modify_rows(
            """INSERT INTO opening_times (gym_id, monday, tuesday, wednesday, thursday, friday, saturday, sunday) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                new_gym.username,
                new_gym.opening_times["monday"],
                new_gym.opening_times["tuesday"],
                new_gym.opening_times["wednesday"],
                new_gym.opening_times["thursday"],
                new_gym.opening_times["friday"],
                new_gym.opening_times["saturday"],
                new_gym.opening_times["sunday"],
            ),
        )

        session["user"] = new_gym
        return render_template("gym_times.html")


@app.route("/machines", methods=["GET", "POST"])
@login_required
@gym_only
def machines():
    if request.method == "GET":
        return render_template("machines.html", rows=session["user"].machines)
    if request.method == "POST":
        gym_service = GymService
        new_gym = session["user"]
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
            (session["user_id"], machine_id),
        )

        if dup_check:
            old_amount = dup_check[0]
            new_amount = old_amount + amount
            modify_rows(
                """UPDATE gym_machines SET amount = %s WHERE gym_id = %s AND machine_id = %s""",
                (new_amount, session["user_id"], machine_id),
            )

        else:
            modify_rows(
                """INSERT INTO gym_machines (gym_id, machine_id, machine_name, amount) VALUES (%s, %s, %s, %s)""",
                (
                    session["user_id"],
                    machine_id,
                    machine,
                    new_gym.machines[machine],
                ),
            )

        session["user"] = new_gym

        return render_template("machines.html", rows=session["user"].machines)


@app.route("/repairing", methods=["GET", "POST"])
@login_required
@gym_only
def repairing():
    if request.method == "GET":
        return render_template("repairing.html", rows=session["user"].repairing)
    elif request.method == "POST":
        gym_service = GymService
        gym = session["user"]
        try:
            machine, amount = request.form.get("machine"), int(
                request.form.get("amount")
            )
        except ValueError:
            flash("Please enter an integer")
            return redirect("/repairing")

        machine_id = fetch_row(
            """SELECT machine_id FROM machine WHERE name = %s""", (machine,)
        )

        dup_check = fetch_row(
            """SELECT amount FROM gym_machines WHERE gym_id = %s AND machine_id = %s""",
            (session["user_id"], machine_id),
        )

        if not dup_check:
            flash("You do not currently own any of this machine")
            return redirect("/repairing")

        old_amount = dup_check[0]
        if amount > old_amount:
            flash(
                f"Please enter an amount less than or equal to your current holdings for this machine: {old_amount}"
            )
            return redirect("/repairing")

        new_amount = old_amount - amount
        modify_rows(
            """UPDATE gym_machines SET amount = %s WHERE gym_id = %s AND machine_id = %s""",
            (new_amount, session["user_id"], machine_id),
        )

        dup_check = fetch_row(
            """SELECT amount FROM repairing WHERE gym_id = %s AND machine_id = %s""",
            (session["user_id"], machine_id),
        )

        if not dup_check:
            modify_rows(
                """INSERT INTO repairing (gym_id, machine_id, machine_name, amount) VALUES (%s, %s, %s, %s)""",
                (session["user_id"], machine_id, machine, amount),
            )
        else:
            old_amount = dup_check[0]
            new_amount = old_amount + amount
            modify_rows(
                """UPDATE repairing SET amount = %s WHERE gym_id = %s AND machine_id = %s""",
                (new_amount, session["user_id"], machine_id),
            )

        # add object code
        gym = gym_service.remove_machines(gym=gym, machine=machine, amount=amount)
        gym = gym_service.add_to_repair(gym=gym, machine=machine, amount=amount)
        return redirect("/repairing")


@app.route("/logout")
@login_required
def logout():
    session["user_id"] = None
    try:
        if session["username"]:
            session["username"] = None
        if session["user"]:
            session["user"] = None
        return render_template("login.html")
    except KeyError:
        return render_template("login.html")


if __name__ == "__main__":
    socketio.run(app, debug=True)
