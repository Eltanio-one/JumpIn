from functools import wraps
from flask import redirect, Flask, session

# from psycopg2 import connect, DatabaseError


# define login_required to ensure that pages can't be accessed without login
def login_required(f):
    # here wraps(f) ensures that the name of the function that is passed in is not lost
    # if wraps(f) wasn't used, the docstring of the passed function would have been lost
    @wraps(f)
    # define the function that will wrap around the function passed as argument
    def wrap(*args, **kwargs):
        # if noone is logged in
        if session.get("user_id") is None:
            # redirect to login
            return redirect("/login")
        # otherwise call the function that we are wrapping! (in login_required case, will be loading a page that required login)
        return f(*args, **kwargs)

    # then return wrap function (aka call the wrap function)
    return wrap


# def fetch_row(query: str, arguments: tuple = None) -> list:
#     try:
#         conn = connect(
#             host="host.docker.internal",
#             user="postgres",
#             password="postgres",
#             dbname="to-do",
#             port=5432,
#         )
#         with conn:
#             with conn.cursor() as cur:
#                 cur.execute(query, arguments)
#                 rows = cur.fetchone()
#                 return rows
#     except (Exception, DatabaseError) as error:
#         print(error)


# def fetch_rows(query: str, arguments: tuple = None) -> list:
#     try:
#         conn = connect(
#             host="host.docker.internal",
#             user="postgres",
#             password="postgres",
#             dbname="to-do",
#             port=5432,
#         )
#         with conn:
#             with conn.cursor() as cur:
#                 cur.execute(query, arguments)
#                 rows = cur.fetchall()
#                 return rows
#     except (Exception, DatabaseError) as error:
#         print(error)


# def modify_rows(query: str, arguments: tuple = None) -> None:
#     try:
#         conn = connect(
#             host="host.docker.internal",
#             user="postgres",
#             password="postgres",
#             dbname="to-do",
#             port=5432,
#         )
#         with conn:
#             with conn.cursor() as cur:
#                 cur.execute(query, arguments)
#                 conn.commit()
#     except (Exception, DatabaseError) as error:
#         print(error)


# def reformat_rows(rows: tuple) -> list:
#     return_rows = []
#     for row in rows:
#         return_rows.append("".join(row))
#     return return_rows
