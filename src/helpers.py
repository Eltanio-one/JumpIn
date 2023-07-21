from functools import wraps
from flask import redirect, Flask, session
from psycopg2 import connect, DatabaseError
from keys import HOST, USERNAME, PASSWORD, DBNAME, PORT


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
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
