from psycopg2 import connect, DatabaseError
from keys import HOST, USERNAME, PASSWORD, DBNAME, PORT


def create_tables():
    """initialise tables in postgresql database"""
    commands = (
        """
        CREATE TABLE users (
            user_id SERIAL PRIMARY KEY,
            username VARCHAR(255),
            email VARCHAR(255),
            name VARCHAR(255),
            date_of_birth VARCHAR(255),
            account_creation VARCHAR(255),
            hashed_password VARCHAR(255)
        )
        """,
        """
        CREATE TABLE gym (
            gym_id SERIAL PRIMARY KEY,
            gym_name VARCHAR(255),
            contact_email VARCHAR(255),
            address VARCHAR(255),
            account_creation VARCHAR(255),
            hashed_password VARCHAR(255)
        )
        """,
        """
        CREATE TABLE machine (
            machine_id SERIAL PRIMARY KEY,
            name VARCHAR(255)
        )
        """,
        """
        CREATE TABLE languages (
            id SERIAL PRIMARY KEY,
            user_id INT,
            language VARCHAR(255),
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE friends (
            id SERIAL PRIMARY KEY,
            user_id INT,
            friends VARCHAR(255),
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE usage (
            id SERIAL PRIMARY KEY,
            user_id INT,
            machine_id INT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE CASCADE,
            FOREIGN KEY (machine_id) REFERENCES machine (machine_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE gym_machines (
            id SERIAL PRIMARY KEY,
            gym_id INT,
            machine_id INT,
            machine_name VARCHAR(255),
            amount INT,
            FOREIGN KEY (gym_id) REFERENCES gym (gym_id) ON UPDATE CASCADE ON DELETE CASCADE,
            FOREIGN KEY (machine_id) REFERENCES machine (machine_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE repairing (
            id SERIAL PRIMARY KEY,
            gym_id INT,
            machine_id INT,
            machine_name VARCAHR(255),
            amount INT,
            FOREIGN KEY (gym_id) REFERENCES gym (gym_id) ON UPDATE CASCADE ON DELETE CASCADE,
            FOREIGN KEY (machine_id) REFERENCES machine (machine_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE members (
            id SERIAL PRIMARY KEY,
            gym_id INT,
            user_id INT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE CASCADE,
            FOREIGN KEY (gym_id) REFERENCES gym (gym_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE opening_times (
            id SERIAL PRIMARY KEY,
            gym_id INT,
            monday VARCHAR(255),
            tuesday VARCHAR(255),
            wednesday VARCHAR(255),
            thursday VARCHAR(255),
            friday VARCHAR(255),
            saturday VARCHAR(255),
            sunday VARCHAR(255),
            FOREIGN KEY (gym_id) REFERENCES gym (gym_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE sessions (
            session_id SERIAL PRIMARY KEY,
            participants INT,
            machines INT,
            booking_date VARCHAR(255),
            session_date VARCHAR(255),
            FOREIGN KEY (participants) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE CASCADE,
            FOREIGN KEY (machines) REFERENCES machine (machine_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE user_session (
            id SERIAL PRIMARY KEY,
            user_id INT,
            request_time TIMESTAMP,
            machine_list VARCHAR[],
            compared_users INT[],
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON UPDATE CASCADE ON DELETE CASCADE
        )
        """)
    
    try:
        conn = connect(
            host=HOST,
            user=USERNAME,
            password=PASSWORD,
            dbname=DBNAME,
            port=PORT,
        )
        cur = conn.cursor()
        for command in commands:
            cur.execute(command)
        cur.close()
        conn.commit()
    except (Exception, DatabaseError) as error:
        print(error)
    
if __name__ == "__main__":
    create_tables()