from functools import wraps
from flask import redirect, Flask, session, flash
from psycopg2 import connect, DatabaseError
from src.keys import HOST, USERNAME, PASSWORD, DBNAME, PORT
from string import punctuation
from re import fullmatch
import numpy as np
from datetime import datetime
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/login")
        return f(*args, **kwargs)

    return wrap


# create a helper function to ensure that only gyms can access gym related sites?
def gym_only(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("username"):
            flash("Access Denied")
            return redirect("/")
        return f(*args, **kwargs)

    return wrap


def fetch_row(query: str, arguments: tuple = None) -> list:
    try:
        conn = connect(
            host=HOST,
            user=USERNAME,
            password=PASSWORD,
            dbname=DBNAME,
            port=PORT,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, arguments)
                rows = cur.fetchone()
                return rows
    except (Exception, DatabaseError) as error:
        print(error)


def fetch_rows(query: str, arguments: tuple = None) -> list:
    try:
        conn = connect(
            host=HOST,
            user=USERNAME,
            password=PASSWORD,
            dbname=DBNAME,
            port=PORT,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, arguments)
                rows = cur.fetchall()
                return rows
    except (Exception, DatabaseError) as error:
        print(error)


def modify_rows(query: str, arguments: tuple = None) -> None:
    try:
        conn = connect(
            host=HOST,
            user=USERNAME,
            password=PASSWORD,
            dbname=DBNAME,
            port=PORT,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, arguments)
                conn.commit()
    except (Exception, DatabaseError) as error:
        print(error)


def reformat_rows(rows: tuple) -> list:
    return_rows = []
    for row in rows:
        return_rows.append("".join(row))
    return return_rows


def verify_password(password: str) -> bool:
    return (
        len(password) >= 8
        and any([char.isdigit() for char in password])
        and any([char.isupper() for char in password])
        and any([char in punctuation for char in password])
    )


def verify_email(email: str) -> bool:
    return fullmatch(
        r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        email,
    )


def matching_algorithm(rows: list) -> dict:
    matches = np.zeros((len(rows), len(rows[0][1])))
    for i, _ in enumerate(rows):
        for j, _ in enumerate(rows):
            if i == j:
                continue
            matches[i][j] = len(list(np.intersect1d(rows[i][1], rows[j][1])))
    matches_output = {}
    for i, _ in enumerate(matches):
        max_for_row = max(matches[i])
        if max_for_row == 0:
            continue
        matches_output[rows[i][2]] = list()
        for j, _ in enumerate(matches[i]):
            if matches[i][j] == max_for_row:
                matches_output[rows[i][2]].append(rows[j][2])
    for i, _ in enumerate(rows):
        if not matches_output.get(rows[i][2]):
            matches_output[rows[i][2]] = ["no matches"]
    return matches_output


def machine_matches(user_id: int, rows: list) -> dict:
    for i, row in enumerate(rows):
        if user_id == row[0]:
            user_machines = row[1]
            del rows[i]
    matches_output = {}
    for i, _ in enumerate(rows):
        matches_output[rows[i][2]] = []
    for i, row in enumerate(rows):
        for j, machine in enumerate(row[1]):
            if user_machines[j] == row[1][j]:
                matches_output[row[2]].append(machine)
        if not matches_output[row[2]]:
            matches_output[row[2]] = "no matches"
    return matches_output


def get_time() -> str:
    now = datetime.now()
    return now.strftime("%d/%m/%Y")


def check_hour() -> str:
    now = datetime.now()
    current_time = now.strftime("%H")
    current_time = int(current_time)
    if current_time < 12 and current_time > 5:
        return "Good Morning,"
    elif current_time >= 12 and current_time < 17:
        return "Good Afternoon,"
    else:
        return "Good Evening,"
