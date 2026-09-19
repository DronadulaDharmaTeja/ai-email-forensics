import mysql.connector
from mysql.connector import Error
from getpass import getpass


DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "database": "email_forensics_db",
}


def get_connection():
    password = getpass("MySQL password: ")

    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        user=DB_CONFIG["user"],
        password=password,
        database=DB_CONFIG["database"],
    )


def test_connection():
    connection = None

    try:
        connection = get_connection()

        if connection.is_connected():
            print("MYSQL DATABASE: PASS")
            print("HOST:", DB_CONFIG["host"])
            print("DATABASE:", DB_CONFIG["database"])

    except Error as e:
        print("MYSQL DATABASE: FAIL")
        print("ERROR:", e)

    finally:
        if connection and connection.is_connected():
            connection.close()
            print("MYSQL CONNECTION CLOSED")


if __name__ == "__main__":
    test_connection()