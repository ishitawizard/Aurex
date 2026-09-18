
from fastapi import FastAPI,HTTPException
from pydantic import BaseModel
from database import get_connection
from datetime import datetime
from evidence_service import verify_document

app = FastAPI()
class CaseCreate(BaseModel):
    title: str
    description: str
    created_by: str


@app.get("/")
def home():
    return {
        "message": "Aurex Backend is working"
    }


@app.get("/db-test")
def database_test():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM cases")
    case_count = cursor.fetchone()[0]

    connection.close()

    return {
        "database": "connected",
        "total_cases": case_count
    }

@app.get("/cases")
def get_cases():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, case_id, title, description, created_by, created_at
        FROM cases
    """)

    rows = cursor.fetchall()

    connection.close()

    cases = []

    for row in rows:
        cases.append({
            "id": row[0],
            "case_id": row[1],
            "title": row[2],
            "description": row[3],
            "created_by": row[4],
            "created_at": row[5]
        })

    return {
        "cases": cases
    }

@app.get("/cases/{case_id}")
def get_case(case_id: str):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, case_id, title, description, created_by, created_at
        FROM cases
        WHERE case_id = ?
    """, (case_id,))

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return {
            "error": "Case not found"
        }

    return {
        "id": row[0],
        "case_id": row[1],
        "title": row[2],
        "description": row[3],
        "created_by": row[4],
        "created_at": row[5]
    }

@app.post("/cases")
def create_case(case: CaseCreate):
    connection = get_connection()
    cursor = connection.cursor()

    case_id = "AUX-" + datetime.now().strftime("%Y%m%d%H%M%S")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO cases
        (case_id, title, description, created_by, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        case_id,
        case.title,
        case.description,
        case.created_by,
        created_at
    ))

    connection.commit()

    connection.close()

    return {
        "message": "Case created successfully",
        "case_id": case_id,
        "title": case.title,
        "description": case.description,
        "created_by": case.created_by,
        "created_at": created_at
    }

@app.delete("/cases/{case_id}")
def delete_case(case_id: str):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM cases
        WHERE case_id = ?
    """, (case_id,))

    connection.commit()

    deleted_rows = cursor.rowcount

    connection.close()

    if deleted_rows == 0:
        return {
            "error": "Case not found"
        }

    return {
        "message": "Case deleted successfully",
        "case_id": case_id
    }

@app.get("/evidence")
def get_evidence():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT document_id, case_id, filename,
               sha256, uploaded_by, uploaded_at, status
        FROM documents
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    evidence = []

    for row in rows:
        evidence.append({
            "document_id": row[0],
            "case_id": row[1],
            "filename": row[2],
            "sha256": row[3],
            "uploaded_by": row[4],
            "uploaded_at": row[5],
            "status": row[6]
        })

    return {
        "evidence": evidence
    }

@app.get("/evidence/{document_id}/verify")
def verify_evidence(document_id: str):
    result = verify_document(
        document_id,
        "Backend API"
    )

    if result is None:
        return {
            "error": "Evidence not found",
            "document_id": document_id
        }

    return result

@app.get("/audit-logs")
def get_audit_logs():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            document_id,
            case_id,
            action,
            performed_by,
            timestamp,
            previous_hash,
            hash
        FROM audit_logs
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    logs = []

    for row in rows:
        logs.append({
            "id": row[0],
            "document_id": row[1],
            "case_id": row[2],
            "action": row[3],
            "performed_by": row[4],
            "timestamp": row[5],
            "previous_hash": row[6],
            "hash": row[7]
        })

    return {
        "audit_logs": logs
    }

@app.get("/audit-logs/{document_id}")
def get_document_audit_logs(document_id: str):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            document_id,
            case_id,
            action,
            performed_by,
            timestamp,
            previous_hash,
            hash
        FROM audit_logs
        WHERE document_id = ?
        ORDER BY id ASC
    """, (document_id,))

    rows = cursor.fetchall()
    connection.close()

    if not rows:
        return {
            "error": "No audit logs found",
            "document_id": document_id
        }

    logs = []

    for row in rows:
        logs.append({
            "id": row[0],
            "document_id": row[1],
            "case_id": row[2],
            "action": row[3],
            "performed_by": row[4],
            "timestamp": row[5],
            "previous_hash": row[6],
            "hash": row[7]
        })

    return {
        "document_id": document_id,
        "audit_logs": logs
    }

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login_user(login: LoginRequest):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT username, role
        FROM users
        WHERE username = ?
        AND password = ?
    """, (
        login.username,
        login.password
    ))

    user = cursor.fetchone()
    connection.close()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    return {
        "message": "Login successful",
        "username": user[0],
        "role": user[1]
    }

@app.delete("/evidence/{document_id}")
def delete_evidence(document_id: str):
    conn = get_connection()
    cur = conn.cursor()

    # Find the evidence record
    cur.execute(
        """
        SELECT document_id, case_id, filename
        FROM documents
        WHERE document_id = ?
        """,
        (document_id,),
    )

    document = cur.fetchone()

    if document is None:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Evidence not found",
        )

    document_id, case_id, filename = document

    # Delete the database record
    cur.execute(
        """
        DELETE FROM documents
        WHERE document_id = ?
        """,
        (document_id,),
    )

    conn.commit()
    conn.close()

    # Delete the encrypted file if it exists
    file_path = os.path.join(
        DOCUMENT_STORAGE_DIR,
        document_id
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    return {
        "status": "success",
        "message": "Evidence deleted successfully",
        "document_id": document_id,
        "case_id": case_id,
    }