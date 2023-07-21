from psycopg2 import connect, DatabaseError
from keys import HOST, USERNAME, PASSWORD, DBNAME, PORT

machines = [
    "chest press",
    "pectoral fly",
    "adjustable bench",
    "incline bench",
    "decline bench",
    "olympic weight bench",
    "preacher curl bench",
    "arm curl bench",
    "arm extension machine",
    "seated dip machine",
    "tricep press machine",
    "tricep extension machine",
    "shoulder press machine",
    "overhead press machine",
    "lateral raises machine",
    "back extension machine",
    "cable row machine",
    "lat pull down machine",
    "glute ham developer",
    "front pull down machine",
    "abdominal bench",
    "ab crunch machine",
    "leg raise / dip tower",
    "ab roller",
    "rotary torso machine",
    "leg press machine",
    "leg extension machine",
    "leg curl machine",
    "leg abduction machine",
    "leg adduction machine",
    "seated calf machine",
    "standing calf machine",
    "calf press machine",
    "donkey kick machine",
    "hack squat machine",
    "reverse hyper machine",
    "smith machine",
    "rowing machine",
    "cable crossover machine",
    "functional trainer",
    "assisted pull up machine"
]

def create_tables():
    """initialise tables in postgresql database"""
    for machine in machines:
        try:
            conn = connect(
                host=HOST,
                user=USERNAME,
                password=PASSWORD,
                dbname=DBNAME,
                port=PORT,
            )
            cur = conn.cursor()
            cur.execute("""INSERT INTO machine (name) VALUES (%s)""", (machine,))
            cur.close()
            conn.commit()
        except (Exception, DatabaseError) as error:
            print(error)
    
if __name__ == "__main__":
    create_tables()