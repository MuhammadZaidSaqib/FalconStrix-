import logging
import os

import mysql.connector
from mysql.connector import Error


def get_db_connection():
    """
    Establish and return a connection to the MariaDB/MySQL database.
    Override with env: MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE.
    """
    try:
        connection = mysql.connector.connect(
            host=os.environ.get('MYSQL_HOST', '127.0.0.1'),
            user=os.environ.get('MYSQL_USER', 'root'),
            password=os.environ.get('MYSQL_PASSWORD', ''),
            database=os.environ.get('MYSQL_DATABASE', 'hidrs_db'),
        )
        if connection.is_connected():
            return connection
    except Error as e:
        logging.error(f"Error while connecting to MySQL: {e}")
    return None

def execute_query(query, params=None):
    """ Executes a single query that updates/inserts data. """
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor.lastrowid
        except Error as e:
            logging.error(f"Query error: {e}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    return None

def fetch_query(query, params=None, fetchall=True):
    """ Executes a select query and returns results. """
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True) # Return results as dict
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            if fetchall:
                return cursor.fetchall()
            else:
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Fetch error: {e}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    return []
