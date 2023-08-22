from functools import wraps
from flask import redirect, current_app, session, flash
from psycopg2 import connect, DatabaseError
from src.keys import HOST, USERNAME, PASSWORD, DBNAME, PORT
from string import punctuation
from re import fullmatch
import numpy as np
from datetime import datetime
import sys
import os
import random
from string import ascii_uppercase
from typing import Callable

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


def login_required(f) -> Callable:
    """
    Ensure user is logged in.
    """

    @wraps(f)
    def wrap(*args, **kwargs):
        if current_app.config.get("LOGIN_DISABLED", True):
            return f(*args, **kwargs)
        elif not session.get("user_id"):
            return redirect("/login")
        return f(*args, **kwargs)

    return wrap


def gym_only(f) -> Callable:
    """
    Ensure gym is logged in.
    """

    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("username"):
            flash("Access Denied")
            return redirect("/")
        return f(*args, **kwargs)

    return wrap


def fetch_row(query: str, arguments: tuple = None) -> list:
    """
    Query postgresql database for one row.
    """
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
    """
    Query postgresql database for multiple rows.
    """
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


def fetch_dict(query: str, arguments: tuple = None) -> dict:
    """
    Query postgresql database for a dictionary.
    """
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
                columns = [column[0] for column in cur.description]
                results = []
                for row in cur.fetchall():
                    results.append(dict(zip(columns, row)))
                return results
    except (Exception, DatabaseError) as error:
        print(error)


def modify_rows(query: str, arguments: tuple = None) -> None:
    """
    Query postgresql database for to modify an entry.
    """
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


def verify_password(password: str) -> bool:
    """
    Ensure password meets criteria.
    """
    return (
        len(password) >= 8
        and any([char.isdigit() for char in password])
        and any([char.isupper() for char in password])
        and any([char in punctuation for char in password])
    )


def verify_email(email: str) -> bool:
    """
    Check if email or username provided on login.
    """
    return fullmatch(
        r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        email,
    )


def matching_algorithm(rows: list) -> dict:
    """
    Match users together based on their provided machines and their order of use.
    """
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
    """
    Match users and show which machines they have in common with other users.
    """
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
            matches_output[row[2]] = ["no matches"]
    return matches_output


def get_date() -> str:
    """
    Generate current date.
    """
    now = datetime.now()
    return now.strftime("%d/%m/%Y")


def check_hour() -> str:
    """
    Check current time to generate specific index greeting.
    """
    now = datetime.now()
    current_time = now.strftime("%H")
    current_time = int(current_time)
    if current_time < 12 and current_time > 5:
        return "Good Morning,"
    elif current_time >= 12 and current_time < 17:
        return "Good Afternoon,"
    else:
        return "Good Evening,"


def generate_unique_code(length, rooms):
    """
    Generate unique room code.
    """
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        if code not in rooms:
            break

    return code


def reformat_rows(rows: list) -> list:
    """
    Reformat rows passsed from postgresql query.
    """
    return_rows = []
    for row in rows:
        return_rows.append("".join(row))
    return return_rows
