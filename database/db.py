from database.mysql_connection import get_connection


def execute_query(query, params=None):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(query, params or ())
        connection.commit()

        return True

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


def fetch_all(query, params=None):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(query, params or ())

        return cursor.fetchall()

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


def fetch_one(query, params=None):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(query, params or ())

        return cursor.fetchone()

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()