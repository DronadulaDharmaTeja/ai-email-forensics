import os

import mysql.connector
from mysql.connector import Error
from mysql.connector.pooling import MySQLConnectionPool
from dotenv import load_dotenv


# Load environment variables from .env
load_dotenv()


DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD"),
    "database": os.getenv("MYSQL_DATABASE", "email_forensics_db"),
}


# Create a reusable MySQL connection pool
connection_pool = MySQLConnectionPool(
    pool_name="email_forensics_pool",
    pool_size=5,
    pool_reset_session=True,
    **DB_CONFIG,
)


def get_connection():
    """Get a database connection from the connection pool."""
    return connection_pool.get_connection()


def test_connection():
    """Test MySQL connectivity."""
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