
import sqlite3
import hashlib
from datetime import datetime


DB_NAME = "aurex.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    # ========================================================
    # USERS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # ========================================================
    # CASES
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            created_by TEXT,
            created_at TEXT
        )
    """)

    # ========================================================
    # DOCUMENTS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT UNIQUE NOT NULL,
            case_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT,
            sha256 TEXT NOT NULL,
            uploaded_by TEXT,
            uploaded_at TEXT,
            status TEXT DEFAULT 'Verified'
        )
    """)

    # ========================================================
    # AUDIT LOGS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT,
            case_id TEXT,
            action TEXT,
            performed_by TEXT,
            timestamp TEXT,
            previous_hash TEXT,
            hash TEXT
        )
    """)

    # ========================================================
    # DEMO USERS
    # ========================================================

    demo_users = [
        (
            "Inspector Arjun",
            "inspector@aurex.demo",
            hash_password("1234"),
            "Investigator"
        ),
        (
            "Forensic Analyst",
            "forensic@aurex.demo",
            hash_password("1234"),
            "Forensic Analyst"
        ),
        (
            "Court Officer",
            "court@aurex.demo",
            hash_password("1234"),
            "Court Officer"
        )
    ]

    for user in demo_users:

        try:

            cursor.execute("""
                INSERT INTO users
                (name, email, password, role)
                VALUES (?, ?, ?, ?)
            """, user)

        except sqlite3.IntegrityError:

            pass

    # ========================================================
    # REPAIR OLD AUDIT RECORDS
    # ========================================================

    cursor.execute("""
        SELECT id, hash, previous_hash
        FROM audit_logs
        ORDER BY id ASC
    """)

    audit_rows = cursor.fetchall()

    previous_hash = "GENESIS"

    for row in audit_rows:

        row_id = row[0]
        stored_hash = row[1]
        existing_previous_hash = row[2]

        if not existing_previous_hash:

            cursor.execute("""
                UPDATE audit_logs
                SET previous_hash = ?
                WHERE id = ?
            """, (
                previous_hash,
                row_id
            ))

        previous_hash = stored_hash

    connection.commit()
    connection.close()


if __name__ == "__main__":

    initialize_database()

    print("Aurex database initialized successfully.")
