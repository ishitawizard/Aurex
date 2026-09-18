import streamlit as st
import sqlite3
import hashlib
import os
import mimetypes
import re
from datetime import datetime


from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURATION
# ============================================================

DB_NAME = "aurex.db"
UPLOAD_FOLDER = "aurex_documents"
VAULT_KEY_FILE = "aurex_vault.key"
AES_KEY_SIZE = 256

# Streamlit Community Cloud already owns the Streamlit web server.
# The prototype therefore keeps its FastAPI endpoints in the code, but
# does not start a second Uvicorn process on Community Cloud.
# IMPORTANT: AUREX PRESENTATION MODE
# This file is the complete Streamlit prototype. FastAPI is intentionally NOT
# started inside this process. The UI uses the local application/data layer
# directly so the Streamlit server cannot be hijacked by an API listener.
HOSTED_STREAMLIT = True

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# ZERO-TRUST DOCUMENT VAULT
# ============================================================

def get_vault_key():
    """
    Load the prototype vault key.
    If it does not exist, create a 256-bit AES key.
    Production Aurex would keep this key inside an HSM/KMS.
    """
    if not os.path.exists(VAULT_KEY_FILE):
        key = AESGCM.generate_key(bit_length=AES_KEY_SIZE)
        with open(VAULT_KEY_FILE, "wb") as file:
            file.write(key)
        return key

    with open(VAULT_KEY_FILE, "rb") as file:
        key = file.read()

    if len(key) != 32:
        raise ValueError(
            "Invalid Aurex vault key. "
            "The key must be exactly 256 bits."
        )

    return key


def encrypt_document_bytes(plain_bytes, document_id):
    """Encrypt evidence using AES-256-GCM."""
    key = get_vault_key()
    aes = AESGCM(key)

    # 96-bit nonce is the standard nonce size for GCM.
    nonce = os.urandom(12)

    # Bind the encrypted content to its Aurex document ID.
    associated_data = document_id.encode("utf-8")

    ciphertext = aes.encrypt(
        nonce,
        plain_bytes,
        associated_data
    )

    # Store nonce together with ciphertext.
    return nonce + ciphertext


def decrypt_document_bytes(encrypted_bytes, document_id):
    """Decrypt AES-256-GCM protected evidence."""
    if len(encrypted_bytes) < 13:
        raise ValueError("Encrypted evidence is incomplete.")

    key = get_vault_key()
    aes = AESGCM(key)

    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    associated_data = document_id.encode("utf-8")

    return aes.decrypt(
        nonce,
        ciphertext,
        associated_data
    )


def migrate_existing_documents_to_vault():
    """
    Convert older prototype plaintext evidence files into
    AES-256-GCM encrypted files automatically.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT document_id, file_path
        FROM documents
    """)

    documents = cursor.fetchall()

    for document_id, file_path in documents:
        if not file_path:
            continue

        if file_path.endswith(".enc"):
            continue

        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "rb") as file:
                plain_bytes = file.read()

            encrypted_bytes = encrypt_document_bytes(
                plain_bytes,
                document_id
            )

            encrypted_path = file_path + ".enc"

            with open(encrypted_path, "wb") as file:
                file.write(encrypted_bytes)

            os.remove(file_path)

            cursor.execute("""
                UPDATE documents
                SET file_path = ?, status = ?
                WHERE document_id = ?
            """, (
                encrypted_path,
                "Encrypted & Verified",
                document_id
            ))

        except Exception:
            # Leave the original file untouched if migration fails.
            continue

    connection.commit()
    connection.close()


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    return sqlite3.connect(DB_NAME)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

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

    # Upgrade an older Aurex prototype database automatically.
    cursor.execute("PRAGMA table_info(audit_logs)")
    audit_columns = [row[1] for row in cursor.fetchall()]

    if "previous_hash" not in audit_columns:
        cursor.execute(
            "ALTER TABLE audit_logs ADD COLUMN previous_hash TEXT"
        )

    cursor.execute("""
        SELECT id, document_id, case_id, action, performed_by, timestamp, hash, previous_hash
        FROM audit_logs
        ORDER BY id ASC
    """)
    audit_rows = cursor.fetchall()

    previous_hash_value = "GENESIS"
    for row in audit_rows:
        row_id, document_id, case_id, action, performed_by, timestamp, stored_hash, row_previous = row
        if not row_previous:
            cursor.execute(
                "UPDATE audit_logs SET previous_hash = ? WHERE id = ?",
                (previous_hash_value, row_id)
            )
        previous_hash_value = stored_hash

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

    connection.commit()
    connection.close()

    # Move any older plaintext prototype files into the encrypted vault.
    migrate_existing_documents_to_vault()


# ============================================================
# HASHING
# ============================================================

def calculate_file_hash(uploaded_file):

    file_bytes = uploaded_file.getvalue()

    return hashlib.sha256(
        file_bytes
    ).hexdigest()


def calculate_stored_file_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_user(email, password):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, name, email, role
        FROM users
        WHERE email = ? AND password = ?
    """, (
        email,
        hash_password(password)
    ))

    user = cursor.fetchone()

    connection.close()

    return user


def create_case(
    title,
    description,
    created_by
):

    connection = get_connection()
    cursor = connection.cursor()

    case_id = (
        "AUX-"
        + datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
    )

    cursor.execute("""
        INSERT INTO cases
        (case_id, title, description,
         created_by, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        case_id,
        title,
        description,
        created_by,
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    ))

    connection.commit()
    connection.close()

    return case_id


def get_cases():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT case_id, title, description,
               created_by, created_at
        FROM cases
        ORDER BY id DESC
    """)

    cases = cursor.fetchall()

    connection.close()

    return cases


def get_documents(case_id=None):

    connection = get_connection()
    cursor = connection.cursor()

    if case_id:

        cursor.execute("""
            SELECT document_id, case_id,
                   filename, sha256,
                   uploaded_by, uploaded_at,
                   status
            FROM documents
            WHERE case_id = ?
            ORDER BY id DESC
        """, (case_id,))

    else:

        cursor.execute("""
            SELECT document_id, case_id,
                   filename, sha256,
                   uploaded_by, uploaded_at,
                   status
            FROM documents
            ORDER BY id DESC
        """)

    documents = cursor.fetchall()

    connection.close()

    return documents


def get_audit_logs(document_id=None):

    connection = get_connection()
    cursor = connection.cursor()

    if document_id:

        cursor.execute("""
            SELECT document_id, case_id,
                   action, performed_by,
                   timestamp, previous_hash, hash
            FROM audit_logs
            WHERE document_id = ?
            ORDER BY id ASC
        """, (document_id,))

    else:

        cursor.execute("""
            SELECT document_id, case_id,
                   action, performed_by,
                   timestamp, previous_hash, hash
            FROM audit_logs
            ORDER BY id DESC
        """)

    logs = cursor.fetchall()

    connection.close()

    return logs


def add_audit_log(
    document_id,
    case_id,
    action,
    performed_by
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    connection = get_connection()
    cursor = connection.cursor()

    # Get the hash of the previous audit event.
    cursor.execute("""
        SELECT hash
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 1
    """)

    previous = cursor.fetchone()
    previous_hash = previous[0] if previous else "GENESIS"

    event_data = (
        document_id
        + case_id
        + action
        + performed_by
        + timestamp
        + previous_hash
    )

    event_hash = hashlib.sha256(
        event_data.encode()
    ).hexdigest()

    cursor.execute("""
        INSERT INTO audit_logs
        (document_id, case_id, action,
         performed_by, timestamp, previous_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        document_id,
        case_id,
        action,
        performed_by,
        timestamp,
        previous_hash,
        event_hash
    ))

    connection.commit()
    connection.close()


# ============================================================
# DOCUMENT UPLOAD
# ============================================================

def save_document(
    uploaded_file,
    case_id,
    user_name
):
    # SHA-256 is calculated from the original plaintext file.
    plain_bytes = uploaded_file.getvalue()

    document_hash = hashlib.sha256(
        plain_bytes
    ).hexdigest()

    timestamp = datetime.now().strftime(
        "%Y%m%d%H%M%S"
    )

    document_id = (
        "DOC-"
        + timestamp
        + "-"
        + document_hash[:8]
    )

    safe_filename = (
        uploaded_file.name
        .replace("/", "_")
        .replace("\\", "_")
    )

    # The physical file stored on disk is encrypted.
    file_path = os.path.join(
        UPLOAD_FOLDER,
        document_id + "_" + safe_filename + ".enc"
    )

    encrypted_bytes = encrypt_document_bytes(
        plain_bytes,
        document_id
    )

    with open(file_path, "wb") as file:
        file.write(encrypted_bytes)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO documents
        (document_id, case_id, filename,
         file_path, sha256, uploaded_by,
         uploaded_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        document_id,
        case_id,
        uploaded_file.name,
        file_path,
        document_hash,
        user_name,
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "Encrypted & Verified"
    ))

    connection.commit()
    connection.close()

    add_audit_log(
        document_id,
        case_id,
        "DOCUMENT UPLOADED",
        user_name
    )

    return document_id, document_hash


# ============================================================
# DOCUMENT VERIFICATION
# ============================================================

def get_document_record(document_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT document_id, case_id, filename,
               file_path, sha256, uploaded_by,
               uploaded_at, status
        FROM documents
        WHERE document_id = ?
    """, (document_id,))

    document = cursor.fetchone()
    connection.close()

    return document


def verify_document(
    document_id,
    user_name
):
    document = get_document_record(document_id)

    if not document:
        return None

    (
        document_id,
        case_id,
        filename,
        file_path,
        original_hash,
        uploaded_by,
        uploaded_at,
        status
    ) = document

    if not os.path.exists(file_path):
        add_audit_log(
            document_id,
            case_id,
            "FILE MISSING",
            user_name
        )

        return {
            "valid": False,
            "case_id": case_id,
            "filename": filename,
            "original_hash": original_hash,
            "current_hash": "FILE NOT FOUND"
        }

    try:
        with open(file_path, "rb") as file:
            encrypted_bytes = file.read()

        # Decryption also checks the AES-GCM authentication tag.
        plain_bytes = decrypt_document_bytes(
            encrypted_bytes,
            document_id
        )

        current_hash = hashlib.sha256(
            plain_bytes
        ).hexdigest()

        valid = (
            current_hash == original_hash
        )

        action = (
            "INTEGRITY VERIFIED"
            if valid
            else
            "TAMPER DETECTED"
        )

    except Exception:
        valid = False
        current_hash = "DECRYPTION FAILED / FILE TAMPERED"
        action = "TAMPER DETECTED"

    add_audit_log(
        document_id,
        case_id,
        action,
        user_name
    )

    return {
        "valid": valid,
        "case_id": case_id,
        "filename": filename,
        "original_hash": original_hash,
        "current_hash": current_hash
    }


# ============================================================
# ZERO-TRUST ACCESS CONTROL
# ============================================================

ROLE_ATTRIBUTES = {
    "Investigator": {
        "clearance": "investigative",
        "protected_access": True,
        "description": "Investigation evidence access"
    },
    "Forensic Analyst": {
        "clearance": "forensic",
        "protected_access": True,
        "description": "Forensic evidence access"
    },
    "Court Officer": {
        "clearance": "judicial",
        "protected_access": False,
        "description": "Read-only judicial review"
    }
}


def get_user_attributes(user):
    """Return the attributes used by the prototype ABAC policy."""
    role = user.get("role")

    attributes = ROLE_ATTRIBUTES.get(
        role,
        {
            "clearance": "none",
            "protected_access": False,
            "description": "No protected access"
        }
    )

    return {
        "name": user.get("name"),
        "role": role,
        "clearance": attributes["clearance"],
        "protected_access": attributes["protected_access"],
        "description": attributes["description"]
    }


def authorize_document_access(user, document_id):
    """
    Prototype attribute-based access decision.

    The decision is based on the logged-in user's role,
    clearance attribute and protected-access attribute.
    """
    attributes = get_user_attributes(user)
    document = get_document_record(document_id)

    if not document:
        return {
            "allowed": False,
            "reason": "Document does not exist.",
            "attributes": attributes
        }

    if not attributes["protected_access"]:
        return {
            "allowed": False,
            "reason": (
                f"Role '{attributes['role']}' is restricted "
                "from direct protected-file access."
            ),
            "attributes": attributes
        }

    return {
        "allowed": True,
        "reason": (
            f"Access granted for {attributes['role']} "
            f"with {attributes['clearance']} clearance."
        ),
        "attributes": attributes
    }


def request_protected_document(
    document_id,
    user
):
    """
    Run the zero-trust access decision, then decrypt only
    when the policy allows access.
    """
    document = get_document_record(document_id)

    if not document:
        return {
            "success": False,
            "allowed": False,
            "reason": "Document not found."
        }

    (
        document_id,
        case_id,
        filename,
        file_path,
        original_hash,
        uploaded_by,
        uploaded_at,
        status
    ) = document

    decision = authorize_document_access(
        user,
        document_id
    )

    if not decision["allowed"]:
        add_audit_log(
            document_id,
            case_id,
            "ACCESS DENIED",
            user["name"]
        )

        return {
            "success": False,
            "allowed": False,
            "reason": decision["reason"]
        }

    if not os.path.exists(file_path):
        add_audit_log(
            document_id,
            case_id,
            "ACCESS FAILED - FILE MISSING",
            user["name"]
        )

        return {
            "success": False,
            "allowed": True,
            "reason": "Encrypted evidence file is missing."
        }

    try:
        with open(file_path, "rb") as file:
            encrypted_bytes = file.read()

        plain_bytes = decrypt_document_bytes(
            encrypted_bytes,
            document_id
        )

        # Log successful access only after successful decryption.
        add_audit_log(
            document_id,
            case_id,
            "DOCUMENT ACCESSED",
            user["name"]
        )

        return {
            "success": True,
            "allowed": True,
            "reason": decision["reason"],
            "filename": filename,
            "data": plain_bytes
        }

    except Exception:
        add_audit_log(
            document_id,
            case_id,
            "ACCESS FAILED - DECRYPTION ERROR",
            user["name"]
        )

        return {
            "success": False,
            "allowed": True,
            "reason": (
                "The encrypted evidence could not be "
                "authenticated/decrypted. Possible tampering."
            )
        }


# ============================================================
# SESSION
# ============================================================

def initialize_session():

    if "logged_in" not in st.session_state:

        st.session_state.logged_in = False

    if "user" not in st.session_state:

        st.session_state.user = None


# ============================================================
# VISUAL DESIGN
# ============================================================

def apply_aurex_design():

    st.markdown("""
    <style>

    /* =====================================================
       GLOBAL
    ===================================================== */

    .stApp {
        background: #F6F8FB !important;
    }

    .main {
        background: #F6F8FB !important;
    }

    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1400px !important;
    }


    /* =====================================================
       SIDEBAR
    ===================================================== */

    section[data-testid="stSidebar"] {
        background: #0E1B2A !important;
    }

    section[data-testid="stSidebar"] > div {
        background: #0E1B2A !important;
    }

    section[data-testid="stSidebar"] * {
        color: #E8EEF5 !important;
    }


    /* =====================================================
       HEADINGS
    ===================================================== */

    h1 {
        color: #16324F !important;
        font-weight: 750 !important;
    }

    h2 {
        color: #16324F !important;
    }

    h3 {
        color: #23415E !important;
    }


    /* =====================================================
       TEXT
    ===================================================== */

    p {
        color: #4B5563;
    }


    /* =====================================================
       BUTTONS
    ===================================================== */

    /* Make ALL Streamlit action buttons high-contrast and readable.
       The text itself is forced to white on every nested label element. */
    div.stButton > button,
    div.stDownloadButton > button {

        background: #16324F !important;
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        opacity: 1 !important;

        border: 1px solid #16324F !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        font-size: 15px !important;
        min-height: 42px !important;
        text-shadow: none !important;
    }

    /* Streamlit renders button labels inside p/span/div elements.
       Override any theme text color so labels cannot become gray/invisible. */
    div.stButton > button p,
    div.stButton > button span,
    div.stButton > button div,
    div.stDownloadButton > button p,
    div.stDownloadButton > button span,
    div.stDownloadButton > button div {

        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        opacity: 1 !important;
        font-weight: 700 !important;
        text-shadow: none !important;
    }

    div.stButton > button:hover,
    div.stDownloadButton > button:hover {

        background: #234D70 !important;
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        border-color: #234D70 !important;
    }

    div.stButton > button:hover p,
    div.stButton > button:hover span,
    div.stButton > button:hover div,
    div.stDownloadButton > button:hover p,
    div.stDownloadButton > button:hover span,
    div.stDownloadButton > button:hover div {

        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
    }


    /* =====================================================
       TEXT INPUTS
    ===================================================== */

    .stTextInput input {

        background:
            white !important;

        color:
            #17212B !important;

        border:
            1px solid
            #D8E0E8 !important;

        border-radius:
            8px !important;
    }

    .stTextArea textarea {

        background:
            white !important;

        color:
            #17212B !important;

        border:
            1px solid
            #D8E0E8 !important;

        border-radius:
            8px !important;
    }


    /* =====================================================
       SELECT BOX
    ===================================================== */

    div[data-baseweb="select"] > div {

        background:
            white !important;

        color:
            #17212B !important;

        border-radius:
            8px !important;

        border-color:
            #D8E0E8 !important;
    }


    /* =====================================================
       FILE UPLOADER
    ===================================================== */

    [data-testid="stFileUploader"] {

        background:
            white !important;

        border:
            1px dashed
            #AAB8C5 !important;

        border-radius:
            12px !important;

        padding:
            12px !important;
    }


    /* =====================================================
       METRIC CARDS
    ===================================================== */

    [data-testid="stMetric"] {

        background:
            white !important;

        border:
            1px solid
            #E1E7ED !important;

        border-radius:
            12px !important;

        padding:
            20px !important;
    }

    [data-testid="stMetricLabel"] {

        color:
            #667085 !important;
    }

    [data-testid="stMetricValue"] {

        color:
            #16324F !important;

        font-weight:
            750 !important;
    }


    /* =====================================================
       EXPANDERS
    ===================================================== */

    [data-testid="stExpander"] {

        background:
            white !important;

        border:
            1px solid
            #E1E7ED !important;

        border-radius:
            10px !important;
    }


    /* =====================================================
       CODE / HASH
    ===================================================== */

    [data-testid="stCodeBlock"] {

        border-radius:
            8px !important;
    }


    /* =====================================================
       ALERTS
    ===================================================== */

    [data-testid="stAlert"] {

        border-radius:
            9px !important;
    }


    /* =====================================================
       DIVIDERS
    ===================================================== */

    hr {

        border-color:
            #E1E7ED !important;
    }


    /* =====================================================
       LOGIN
    ===================================================== */

    .login-container {

        background:
            white;

        border:
            1px solid
            #E1E7ED;

        border-radius:
            14px;

        padding:
            25px;

        margin-bottom:
            20px;

        box-shadow:
            0 5px 18px
            rgba(
                15,
                23,
                42,
                0.06
            );
    }

    .login-logo {

        color:
            #16324F;

        font-size:
            30px;

        font-weight:
            800;

        letter-spacing:
            2px;
    }

    .login-subtitle {

        color:
            #667085;

        font-size:
            12px;

        font-weight:
            600;

        letter-spacing:
            1.5px;

        margin-top:
            5px;
    }


    /* =====================================================
       CERTIFICATE
    ===================================================== */

    .certificate {

        background:
            white;

        border:
            1px solid
            #C9D4DF;

        border-radius:
            5px;

        padding:
            35px;

        margin:
            20px 0;

        text-align:
            center;

        box-shadow:
            0 8px 25px
            rgba(
                15,
                23,
                42,
                0.06
            );
    }

    .certificate-brand {

        color:
            #16324F;

        font-size:
            20px;

        font-weight:
            800;

        letter-spacing:
            3px;
    }

    .certificate-title {

        color:
            #23415E;

        font-size:
            23px;

        font-weight:
            700;

        letter-spacing:
            1px;

        margin-top:
            15px;
    }

    </style>
    """, unsafe_allow_html=True)


# ============================================================
# LOGIN PAGE
# ============================================================

def login_page():

    st.markdown("## ◈ AUREX")
    st.caption("SECURE DIGITAL EVIDENCE PLATFORM")

    st.title(
        "Secure Evidence Management"
    )

    st.write(
        "Protecting digital evidence through "
        "cryptographic integrity and controlled access."
    )

    st.divider()

    st.subheader("Sign in")

    email = st.text_input(
        "Email",
        placeholder="Enter your email"
    )

    password = st.text_input(
        "Password",
        type="password",
        placeholder="Enter your password"
    )

    if st.button(
        "Sign In",
        use_container_width=True
    ):

        user = get_user(
            email,
            password
        )

        if user:

            st.session_state.logged_in = True

            st.session_state.user = {
                "id": user[0],
                "name": user[1],
                "email": user[2],
                "role": user[3]
            }

            st.rerun()

        else:

            st.error(
                "Invalid email or password."
            )

    st.divider()

    with st.expander(
        "Demo Access"
    ):

        st.write(
            "**Investigator**"
        )

        st.code(
            "inspector@aurex.demo / 1234"
        )

        st.write(
            "**Forensic Analyst**"
        )

        st.code(
            "forensic@aurex.demo / 1234"
        )

        st.write(
            "**Court Officer**"
        )

        st.code(
            "court@aurex.demo / 1234"
        )


# ============================================================
# DASHBOARD
# ============================================================

def dashboard_page():

    user = st.session_state.user

    st.title(
        "Aurex Command Center"
    )

    st.caption(
        f"{user['name']}  •  {user['role']}"
    )

    cases = get_cases()
    documents = get_documents()
    logs = get_audit_logs()

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Active Cases",
            len(cases)
        )

    with col2:

        st.metric(
            "Evidence Files",
            len(documents)
        )

    with col3:

        st.metric(
            "Audit Events",
            len(logs)
        )

    with col4:

        st.metric(
            "System Status",
            "SECURE"
        )

    st.divider()

    # --------------------------------------------------------
    # SECURITY STATUS
    # --------------------------------------------------------

    st.subheader(
        "Evidence Security Status"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.success(
            "SHA-256 VERIFIED"
        )

        st.caption(
            "Cryptographic fingerprints "
            "protect evidence integrity."
        )

    with col2:

        st.success(
            "CHAIN OF CUSTODY ACTIVE"
        )

        st.caption(
            "Evidence activity is recorded "
            "chronologically."
        )

    with col3:

        st.success(
            "ZERO-TRUST VAULT ACTIVE"
        )

        st.caption(
            "AES-256-GCM encryption and "
            "attribute-based access decisions "
            "protect evidence access."
        )

    st.divider()

    # --------------------------------------------------------
    # RECENT EVIDENCE
    # --------------------------------------------------------

    st.subheader(
        "Recent Evidence"
    )

    if documents:

        for document in documents[:5]:

            (
                document_id,
                case_id,
                filename,
                sha256_hash,
                uploaded_by,
                uploaded_at,
                status
            ) = document

            with st.container(
                border=True
            ):

                col1, col2 = st.columns(
                    [3, 1]
                )

                with col1:

                    st.write(
                        f"**{filename}**"
                    )

                    st.caption(
                        f"Case: {case_id}  •  "
                        f"Document: {document_id}"
                    )

                    st.caption(
                        f"Registered by "
                        f"{uploaded_by}  •  "
                        f"{uploaded_at}"
                    )

                with col2:

                    st.success(
                        status
                    )

    else:

        st.info(
            "No evidence uploaded yet."
        )


# ============================================================
# CASE MANAGEMENT
# ============================================================

def cases_page():

    st.title(
        "Case Management"
    )

    st.caption(
        "Create and manage investigation cases."
    )

    st.subheader(
        "Create New Investigation Case"
    )

    title = st.text_input(
        "Case Title",
        placeholder=(
            "Example: Digital Fraud Investigation"
        )
    )

    description = st.text_area(
        "Case Description",
        placeholder=(
            "Enter investigation details..."
        )
    )

    if st.button(
        "Create Case",
        use_container_width=True
    ):

        if not title.strip():

            st.warning(
                "Please enter a case title."
            )

        else:

            case_id = create_case(
                title,
                description,
                st.session_state.user["name"]
            )

            st.success(
                f"Case created successfully: "
                f"{case_id}"
            )

    st.divider()

    st.subheader(
        "Existing Cases"
    )

    cases = get_cases()

    if not cases:

        st.info(
            "No cases created yet."
        )

        return

    for case in cases:

        (
            case_id,
            title,
            description,
            created_by,
            created_at
        ) = case

        with st.expander(
            f"{case_id} — {title}"
        ):

            st.write(
                description
            )

            st.caption(
                f"Created by {created_by}  •  "
                f"{created_at}"
            )


# ============================================================
# UPLOAD EVIDENCE
# ============================================================

def upload_page():

    st.title(
        "Evidence Ingestion"
    )

    st.caption(
        "Securely register digital evidence "
        "and generate its cryptographic fingerprint."
    )

    cases = get_cases()

    if not cases:

        st.warning(
            "Create a case before uploading evidence."
        )

        return

    case_options = {
        f"{case[0]} — {case[1]}": case[0]
        for case in cases
    }

    selected_case = st.selectbox(
        "Select Case",
        list(case_options.keys())
    )

    case_id = case_options[
        selected_case
    ]

    uploaded_file = st.file_uploader(
        "Choose Evidence File",
        type=[
            "pdf",
            "txt",
            "doc",
            "docx",
            "jpg",
            "jpeg",
            "png",
            "mp4",
            "zip"
        ]
    )

    if uploaded_file:

        st.info(
            f"Selected file: "
            f"{uploaded_file.name}"
        )

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**File Name**"
            )

            st.write(
                uploaded_file.name
            )

        with col2:

            st.write(
                "**File Size**"
            )

            st.write(
                f"{uploaded_file.size:,} bytes"
            )

        if st.button(
            "Secure & Register Evidence",
            use_container_width=True
        ):

            document_id, document_hash = (
                save_document(
                    uploaded_file,
                    case_id,
                    st.session_state.user["name"]
                )
            )

            st.success(
                "Evidence successfully registered."
            )

            st.write(
                f"**Document ID:** "
                f"`{document_id}`"
            )

            st.write(
                "**SHA-256 Fingerprint**"
            )

            st.code(
                document_hash,
                language="text"
            )

            st.info(
                "This SHA-256 fingerprint acts as "
                "the cryptographic identity of the "
                "uploaded file."
            )


# ============================================================
# EVIDENCE VAULT
# ============================================================

def evidence_page():
    st.title(
        "Evidence Vault"
    )

    st.caption(
        "Encrypted evidence, cryptographic verification, "
        "and zero-trust access control."
    )

    st.success(
        "AES-256-GCM ENCRYPTION ACTIVE — "
        "Evidence is encrypted at rest."
    )

    documents = get_documents()

    if not documents:
        st.info(
            "No evidence available."
        )

        return

    user = st.session_state.user
    attributes = get_user_attributes(user)

    st.info(
        f"Current access profile: **{attributes['role']}**  •  "
        f"Clearance: **{attributes['clearance']}**"
    )

    for document in documents:

        (
            document_id,
            case_id,
            filename,
            sha256_hash,
            uploaded_by,
            uploaded_at,
            status
        ) = document

        with st.expander(
            f"{filename} — {document_id}"
        ):

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    f"**Case:** {case_id}"
                )

                st.write(
                    f"**Uploaded by:** {uploaded_by}"
                )

                st.write(
                    f"**Uploaded:** {uploaded_at}"
                )

                st.write(
                    f"**Storage:** AES-256-GCM encrypted"
                )

                st.write(
                    f"**Status:** {status}"
                )

            with col2:

                st.write(
                    "**SHA-256 Fingerprint**"
                )

                st.code(
                    sha256_hash,
                    language="text"
                )

            st.divider()

            st.subheader(
                "Integrity Verification"
            )

            if st.button(
                "Verify Integrity",
                key="verify_" + document_id
            ):

                result = verify_document(
                    document_id,
                    user["name"]
                )

                if result["valid"]:

                    st.success(
                        "INTEGRITY VERIFIED — "
                        "Encrypted evidence decrypted successfully "
                        "and its SHA-256 fingerprint matches."
                    )

                else:

                    st.error(
                        "TAMPERING DETECTED — "
                        "The evidence failed cryptographic verification."
                    )

                st.write(
                    "**Registered Hash**"
                )

                st.code(
                    result["original_hash"]
                )

                st.write(
                    "**Current Hash**"
                )

                st.code(
                    result["current_hash"]
                )

            st.divider()

            st.subheader(
                "Protected File Access"
            )

            access_key = "vault_access_" + document_id
            filename_key = access_key + "_filename"

            if attributes["protected_access"]:

                st.caption(
                    "Your attributes permit protected-file access."
                )

                if st.button(
                    "Request Protected Access",
                    key="access_" + document_id
                ):

                    result = request_protected_document(
                        document_id,
                        user
                    )

                    if result["success"]:

                        st.session_state[access_key] = result["data"]
                        st.session_state[filename_key] = result["filename"]

                        st.success(
                            "ACCESS GRANTED — "
                            "Identity and access attributes verified. "
                            "Evidence decrypted successfully."
                        )

                    else:

                        st.error(
                            result["reason"]
                        )

                if access_key in st.session_state:

                    mime_type = mimetypes.guess_type(
                        st.session_state[filename_key]
                    )[0] or "application/octet-stream"

                    st.download_button(
                        "Download Authorized Evidence",
                        data=st.session_state[access_key],
                        file_name=st.session_state[filename_key],
                        mime=mime_type,
                        key="download_" + document_id
                    )

            else:

                st.caption(
                    "Your current attributes do not permit "
                    "direct protected-file access."
                )

                if st.button(
                    "Request Protected Access",
                    key="denied_access_" + document_id
                ):

                    result = request_protected_document(
                        document_id,
                        user
                    )

                    st.error(
                        "ACCESS DENIED — "
                        + result["reason"]
                    )

                    st.warning(
                        "This denial has been recorded in the "
                        "chain-of-custody audit trail."
                    )


# ============================================================
# CHAIN OF CUSTODY
# ============================================================

def chain_page():

    st.title(
        "Chain of Custody"
    )

    st.caption(
        "Chronological record of evidence activity."
    )

    logs = get_audit_logs()

    if not logs:

        st.info(
            "No audit events recorded."
        )

        return

    for log in logs:

        (
            document_id,
            case_id,
            action,
            performed_by,
            timestamp,
            previous_hash,
            event_hash
        ) = log

        with st.container(
            border=True
        ):

            st.markdown(
                f"### {action}"
            )

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    f"**Document:** `{document_id}`"
                )

                st.write(
                    f"**Case:** `{case_id}`"
                )

            with col2:

                st.write(
                    f"**Officer:** {performed_by}"
                )

                st.write(
                    f"**Time:** {timestamp}"
                )

            st.write(
                "**Event Hash**"
            )

            st.code(
                event_hash,
                language="text"
            )


# ============================================================
# CERTIFICATE
# ============================================================

def certificate_page():

    st.title(
        "Evidence Integrity Certificate"
    )

    st.caption(
        "Generate a formal cryptographic "
        "evidence integrity report."
    )

    documents = get_documents()

    if not documents:

        st.info(
            "No evidence available."
        )

        return

    document_options = {
        f"{d[0]} — {d[2]}": d[0]
        for d in documents
    }

    selected = st.selectbox(
        "Select Evidence",
        list(document_options.keys())
    )

    document_id = document_options[
        selected
    ]

    if st.button(
        "Generate Integrity Certificate",
        use_container_width=True
    ):

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT document_id,
                   case_id,
                   filename,
                   sha256,
                   uploaded_by,
                   uploaded_at
            FROM documents
            WHERE document_id = ?
        """, (document_id,))

        document = cursor.fetchone()

        connection.close()

        if document:

            (
                doc_id,
                case_id,
                filename,
                sha256_hash,
                uploaded_by,
                uploaded_at
            ) = document

            certificate_time = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            st.success(
                "Certificate generated successfully."
            )

            st.divider()

            st.markdown("## ◈ AUREX")
            st.markdown("### DIGITAL EVIDENCE  \nINTEGRITY CERTIFICATE")

            st.write(
                "**Certificate Type:** "
                "Cryptographic Evidence Integrity Report"
            )

            st.write(
                f"**Document ID:** {doc_id}"
            )

            st.write(
                f"**Case ID:** {case_id}"
            )

            st.write(
                f"**Evidence File:** {filename}"
            )

            st.write(
                f"**Registered By:** {uploaded_by}"
            )

            st.write(
                f"**Original Registration:** "
                f"{uploaded_at}"
            )

            st.write(
                f"**Verification Time:** "
                f"{certificate_time}"
            )

            st.subheader(
                "SHA-256 Fingerprint"
            )

            st.code(
                sha256_hash,
                language="text"
            )

            st.success(
                "Cryptographic fingerprint recorded."
            )

            st.info(
                "Prototype certificate. In the production "
                "Aurex system, this workflow would connect "
                "to digital signatures and a permissioned "
                "blockchain ledger."
            )


# ============================================================
# ARCHITECTURE
# ============================================================

def architecture_page():

    st.title(
        "Aurex Architecture"
    )

    st.caption(
        "Technical architecture of the Aurex platform."
    )

    st.subheader(
        "Prototype Architecture"
    )

    st.markdown(
        """
        **1. User Interface**

        Investigator / Forensic Analyst / Court Officer

        ↓

        **2. Aurex Application**

        Case Management  
        Evidence Ingestion  
        Zero-Trust Access Control  
        Verification  
        Audit Trail

        ↓

        **3. Cryptographic Layer**

        SHA-256 Fingerprint Generation  
        AES-256-GCM Encryption

        ↓

        **4. Evidence Storage**

        Encrypted Prototype Local Storage

        ↓

        **5. Audit / Ledger Layer**

        Prototype Immutable-Style Audit Records
        """
    )

    st.divider()

    st.subheader(
        "Production Aurex Architecture"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.info(
            "SHA-256"
        )

        st.write(
            "Cryptographic fingerprint for "
            "every uploaded document."
        )

    with col2:

        st.info(
            "Hyperledger Fabric"
        )

        st.write(
            "Permissioned ledger for audit trail, "
            "transfer events and metadata."
        )

    with col3:

        st.info(
            "Encrypted Off-Chain Storage"
        )

        st.write(
            "Large investigative files stored "
            "separately and linked through "
            "cryptographic hashes."
        )

    st.divider()

    st.warning(
        "Prototype Notice: AES-256-GCM encryption and "
        "zero-trust access control are implemented locally. "
        "Production Aurex would use HSM/KMS-backed keys, "
        "permissioned blockchain infrastructure and "
        "digital signatures."
    )



# ============================================================
# AUREX CLASS 3 - COMPLETE PROTOTYPE EXTENSIONS
# ============================================================
# These extensions complete the front-end prototype around the
# existing security core. They are intentionally local/prototype
# implementations; FastAPI and production services can replace
# these functions later without changing the UI concepts.

EXTENDED_ROLES = {
    "Investigator": {
        "can_create_case": True,
        "can_upload": True,
        "can_access_evidence": True,
        "can_review": False,
        "can_manage_workflow": True,
        "can_generate_reports": True,
    },
    "Forensic Analyst": {
        "can_create_case": True,
        "can_upload": True,
        "can_access_evidence": True,
        "can_review": True,
        "can_manage_workflow": True,
        "can_generate_reports": True,
    },
    "Court Officer": {
        "can_create_case": False,
        "can_upload": False,
        "can_access_evidence": False,
        "can_review": False,
        "can_manage_workflow": False,
        "can_generate_reports": True,
    },
}


def role_permission(user, permission):
    role = user.get("role") if user else None
    return EXTENDED_ROLES.get(role, {}).get(permission, False)


def initialize_extended_database():
    """Create the prototype workflow, metadata, indexing and compliance tables."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            user_email TEXT NOT NULL,
            role TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            assigned_by TEXT NOT NULL,
            UNIQUE(case_id, user_email)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            source TEXT DEFAULT '',
            evidence_type TEXT DEFAULT '',
            priority TEXT DEFAULT 'Normal',
            notes TEXT DEFAULT '',
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workflow (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT UNIQUE NOT NULL,
            stage TEXT NOT NULL DEFAULT 'Ingested',
            assigned_to TEXT DEFAULT '',
            reviewer TEXT DEFAULT '',
            decision TEXT DEFAULT 'Pending',
            comments TEXT DEFAULT '',
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT NOT NULL,
            requester TEXT NOT NULL,
            requester_role TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS semantic_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT UNIQUE NOT NULL,
            searchable_text TEXT NOT NULL,
            indexed_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS compliance_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            document_id TEXT DEFAULT '',
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def clear_vault_session_data():
    """Remove decrypted evidence bytes from the Streamlit session."""
    for key in list(st.session_state.keys()):
        if str(key).startswith("vault_access_") or str(key).endswith("_filename"):
            del st.session_state[key]


def get_case_record(case_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT case_id, title, description, created_by, created_at
        FROM cases
        WHERE case_id = ?
    """, (case_id,))
    row = cursor.fetchone()
    connection.close()
    return row


def get_case_documents(case_id):
    return get_documents(case_id)


def get_all_users():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT id, name, email, role
        FROM users
        ORDER BY name ASC
    """)
    rows = cursor.fetchall()
    connection.close()
    return rows


def assign_case_member(case_id, user_email, assigned_by):
    user = None
    for row in get_all_users():
        if row[2] == user_email:
            user = row
            break

    case = get_case_record(case_id)
    if not case:
        return False, "Case does not exist."

    if not user:
        return False, "Selected user does not exist."

    connection = get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO case_members
            (case_id, user_email, role, assigned_at, assigned_by)
            VALUES (?, ?, ?, ?, ?)
        """, (
            case_id,
            user[2],
            user[3],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            assigned_by,
        ))
        connection.commit()
    finally:
        connection.close()

    add_audit_log(
        "CASE-" + case_id,
        case_id,
        "CASE MEMBER ASSIGNED",
        assigned_by,
    )
    return True, f"{user[1]} assigned to {case_id}."


def get_case_members(case_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT user_email, role, assigned_at, assigned_by
        FROM case_members
        WHERE case_id = ?
        ORDER BY id DESC
    """, (case_id,))
    rows = cursor.fetchall()
    connection.close()
    return rows


def get_evidence_metadata(document_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT document_id, description, tags, source, evidence_type,
               priority, notes, updated_at, updated_by
        FROM evidence_metadata
        WHERE document_id = ?
    """, (document_id,))
    row = cursor.fetchone()
    connection.close()
    return row


def upsert_evidence_metadata(
    document_id,
    description,
    tags,
    source,
    evidence_type,
    priority,
    notes,
    updated_by,
):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO evidence_metadata
        (document_id, description, tags, source, evidence_type,
         priority, notes, updated_at, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(document_id) DO UPDATE SET
            description=excluded.description,
            tags=excluded.tags,
            source=excluded.source,
            evidence_type=excluded.evidence_type,
            priority=excluded.priority,
            notes=excluded.notes,
            updated_at=excluded.updated_at,
            updated_by=excluded.updated_by
    """, (
        document_id,
        description.strip(),
        tags.strip(),
        source.strip(),
        evidence_type.strip(),
        priority,
        notes.strip(),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        updated_by,
    ))
    connection.commit()
    connection.close()

    document = get_document_record(document_id)
    if document:
        rebuild_semantic_index(document_id)

    add_audit_log(
        document_id,
        document[1] if document else "",
        "EVIDENCE METADATA UPDATED",
        updated_by,
    )


def initialize_document_metadata(document_id, user_name):
    if not get_evidence_metadata(document_id):
        upsert_evidence_metadata(
            document_id,
            "",
            "",
            "",
            "Digital Evidence",
            "Normal",
            "",
            user_name,
        )


def get_workflow(document_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT document_id, stage, assigned_to, reviewer,
               decision, comments, updated_at, updated_by
        FROM workflow
        WHERE document_id = ?
    """, (document_id,))
    row = cursor.fetchone()
    connection.close()
    return row


def ensure_workflow(document_id, user_name):
    if get_workflow(document_id):
        return

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO workflow
        (document_id, stage, assigned_to, reviewer, decision,
         comments, updated_at, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        document_id,
        "Ingested",
        "",
        "",
        "Pending",
        "",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        user_name,
    ))
    connection.commit()
    connection.close()


def update_workflow(
    document_id,
    stage,
    assigned_to,
    reviewer,
    decision,
    comments,
    user_name,
):
    document = get_document_record(document_id)
    if not document:
        return False, "Document not found."

    ensure_workflow(document_id, user_name)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE workflow
        SET stage = ?,
            assigned_to = ?,
            reviewer = ?,
            decision = ?,
            comments = ?,
            updated_at = ?,
            updated_by = ?
        WHERE document_id = ?
    """, (
        stage,
        assigned_to.strip(),
        reviewer.strip(),
        decision,
        comments.strip(),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        user_name,
        document_id,
    ))
    connection.commit()
    connection.close()

    add_audit_log(
        document_id,
        document[1],
        "WORKFLOW UPDATED: " + stage,
        user_name,
    )
    record_compliance_event(
        document[1],
        document_id,
        "WORKFLOW",
        f"Stage={stage}; Decision={decision}",
        user_name,
    )
    return True, "Workflow updated."


def record_access_request(document_id, user, decision, reason):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO access_requests
        (document_id, requester, requester_role, decision, reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        document_id,
        user["name"],
        user["role"],
        decision,
        reason,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    connection.commit()
    connection.close()


def record_compliance_event(case_id, document_id, event_type, details, user_name):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO compliance_events
        (case_id, document_id, event_type, details, performed_by, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        document_id or "",
        event_type,
        details,
        user_name,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    connection.commit()
    connection.close()


def get_compliance_events(case_id=None):
    connection = get_connection()
    cursor = connection.cursor()

    if case_id:
        cursor.execute("""
            SELECT case_id, document_id, event_type, details,
                   performed_by, timestamp
            FROM compliance_events
            WHERE case_id = ?
            ORDER BY id DESC
        """, (case_id,))
    else:
        cursor.execute("""
            SELECT case_id, document_id, event_type, details,
                   performed_by, timestamp
            FROM compliance_events
            ORDER BY id DESC
        """)

    rows = cursor.fetchall()
    connection.close()
    return rows


def tokenize_for_search(text):
    words = re.findall(r"[a-zA-Z0-9_]+", (text or "").lower())
    stop_words = {
        "the", "and", "for", "with", "from", "this", "that",
        "file", "document", "case", "evidence", "a", "an", "of",
        "to", "in", "on", "is", "by", "or", "as",
    }
    return [word for word in words if len(word) > 2 and word not in stop_words]


def rebuild_semantic_index(document_id):
    document = get_document_record(document_id)
    if not document:
        return

    metadata = get_evidence_metadata(document_id)
    case = get_case_record(document[1])

    parts = [
        document[2],
        document[1],
        document[4],
        document[5],
        document[6],
    ]

    if case:
        parts.extend([case[1], case[2], case[3]])

    if metadata:
        parts.extend([
            metadata[1], metadata[2], metadata[3], metadata[4],
            metadata[5], metadata[6],
        ])

    searchable_text = " ".join(part or "" for part in parts)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO semantic_index
        (document_id, searchable_text, indexed_at)
        VALUES (?, ?, ?)
        ON CONFLICT(document_id) DO UPDATE SET
            searchable_text=excluded.searchable_text,
            indexed_at=excluded.indexed_at
    """, (
        document_id,
        searchable_text,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    connection.commit()
    connection.close()


def rebuild_all_semantic_indexes():
    for document in get_documents():
        rebuild_semantic_index(document[0])


def semantic_search(query):
    query_tokens = tokenize_for_search(query)
    if not query_tokens:
        return []

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT document_id, searchable_text, indexed_at
        FROM semantic_index
    """)
    rows = cursor.fetchall()
    connection.close()

    results = []

    for document_id, searchable_text, indexed_at in rows:
        text = (searchable_text or "").lower()
        tokens = tokenize_for_search(searchable_text)

        score = 0
        matched = []

        for token in query_tokens:
            if token in tokens:
                score += 2
                matched.append(token)
            elif token in text:
                score += 1
                matched.append(token)

        if score > 0:
            document = get_document_record(document_id)
            if document:
                results.append({
                    "score": score,
                    "document": document,
                    "matched": sorted(set(matched)),
                    "indexed_at": indexed_at,
                })

    results.sort(
        key=lambda item: (item["score"], item["document"][7]),
        reverse=True,
    )
    return results


def get_case_statistics(case_id):
    documents = get_documents(case_id)
    verified = 0
    tampered = 0
    encrypted = 0

    for document in documents:
        status = document[6] or ""
        if "Verified" in status or "Encrypted" in status:
            verified += 1
        if "Tamper" in status:
            tampered += 1
        if "Encrypted" in status:
            encrypted += 1

    return {
        "documents": len(documents),
        "verified": verified,
        "tampered": tampered,
        "encrypted": encrypted,
    }


def verify_audit_chain():
    """Verify the hash linkage of the prototype immutable-style ledger."""
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT id, document_id, case_id, action, performed_by,
               timestamp, previous_hash, hash
        FROM audit_logs
        ORDER BY id ASC
    """)
    rows = cursor.fetchall()
    connection.close()

    previous_hash = "GENESIS"
    failures = []

    for row in rows:
        (
            row_id,
            document_id,
            case_id,
            action,
            performed_by,
            timestamp,
            stored_previous,
            stored_hash,
        ) = row

        if stored_previous != previous_hash:
            failures.append(
                f"Event {row_id}: previous hash linkage mismatch."
            )

        event_data = (
            (document_id or "")
            + (case_id or "")
            + (action or "")
            + (performed_by or "")
            + (timestamp or "")
            + (stored_previous or "")
        )

        expected_hash = hashlib.sha256(
            event_data.encode()
        ).hexdigest()

        if expected_hash != stored_hash:
            failures.append(
                f"Event {row_id}: event hash mismatch."
            )

        previous_hash = stored_hash

    return {
        "valid": len(failures) == 0,
        "events": len(rows),
        "failures": failures,
    }


def update_document_status(document_id, status, user_name):
    document = get_document_record(document_id)
    if not document:
        return False

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE documents
        SET status = ?
        WHERE document_id = ?
    """, (status, document_id))
    connection.commit()
    connection.close()

    add_audit_log(
        document_id,
        document[1],
        "DOCUMENT STATUS: " + status,
        user_name,
    )
    return True


def build_case_report(case_id):
    case = get_case_record(case_id)
    if not case:
        return ""

    documents = get_documents(case_id)
    events = get_compliance_events(case_id)

    lines = [
        "AUREX - DIGITAL EVIDENCE CASE REPORT",
        "=" * 72,
        f"Case ID: {case[0]}",
        f"Title: {case[1]}",
        f"Description: {case[2] or 'N/A'}",
        f"Created By: {case[3]}",
        f"Created At: {case[4]}",
        "",
        "EVIDENCE INVENTORY",
        "-" * 72,
    ]

    for document in documents:
        metadata = get_evidence_metadata(document[0])
        workflow = get_workflow(document[0])

        lines.extend([
            f"Document ID: {document[0]}",
            f"Filename: {document[2]}",
            f"SHA-256: {document[3]}",
            f"Uploaded By: {document[4]}",
            f"Uploaded At: {document[5]}",
            f"Status: {document[6]}",
        ])

        if metadata:
            lines.extend([
                f"Evidence Type: {metadata[4]}",
                f"Priority: {metadata[5]}",
                f"Tags: {metadata[2] or 'None'}",
                f"Source: {metadata[3] or 'Not specified'}",
                f"Description: {metadata[1] or 'Not specified'}",
            ])

        if workflow:
            lines.extend([
                f"Workflow Stage: {workflow[1]}",
                f"Assigned To: {workflow[2] or 'Unassigned'}",
                f"Reviewer: {workflow[3] or 'Unassigned'}",
                f"Decision: {workflow[4]}",
                f"Workflow Comments: {workflow[5] or 'None'}",
            ])

        lines.append("")

    lines.extend([
        "COMPLIANCE EVENTS",
        "-" * 72,
    ])

    for event in events:
        lines.append(
            f"{event[5]} | {event[2]} | {event[4]} | {event[3]}"
        )

    chain = verify_audit_chain()
    lines.extend([
        "",
        "AUDIT LEDGER INTEGRITY",
        "-" * 72,
        f"Ledger Events Checked: {chain['events']}",
        f"Ledger Valid: {'YES' if chain['valid'] else 'NO'}",
    ])

    if chain["failures"]:
        lines.extend(chain["failures"])

    lines.extend([
        "",
        "SECURITY MODEL",
        "-" * 72,
        "SHA-256 evidence fingerprinting",
        "AES-256-GCM encrypted evidence at rest",
        "Attribute-based prototype access control",
        "Hash-linked chain-of-custody audit records",
        "Workflow and compliance event logging",
        "",
        "PROTOTYPE NOTICE",
        "-" * 72,
        "This report is generated by the Aurex prototype.",
        "Production deployment would connect these interfaces to",
        "FastAPI services, HSM/KMS key management, object storage,",
        "digital signatures, and a permissioned ledger.",
    ])

    return "\n".join(lines)


def create_case_and_log(title, description, user_name):
    case_id = create_case(title, description, user_name)
    add_audit_log(
        "CASE-" + case_id,
        case_id,
        "CASE CREATED",
        user_name,
    )
    record_compliance_event(
        case_id,
        "",
        "CASE",
        "Investigation case created.",
        user_name,
    )
    return case_id


def save_document_with_extensions(uploaded_file, case_id, user_name):
    document_id, document_hash = save_document(
        uploaded_file,
        case_id,
        user_name,
    )
    initialize_document_metadata(document_id, user_name)
    ensure_workflow(document_id, user_name)
    rebuild_semantic_index(document_id)

    record_compliance_event(
        case_id,
        document_id,
        "INGESTION",
        f"Evidence registered with SHA-256 {document_hash}.",
        user_name,
    )

    return document_id, document_hash


def enhanced_upload_page():
    st.title("Evidence Ingestion")
    st.caption(
        "Register evidence, fingerprint it, encrypt it and prepare "
        "it for forensic workflow."
    )

    user = st.session_state.user

    if not role_permission(user, "can_upload"):
        st.warning(
            "Your role is read-only for evidence ingestion. "
            "Use Evidence Intelligence, Chain of Custody or Compliance."
        )
        return

    cases = get_cases()

    if not cases:
        st.warning("Create a case before uploading evidence.")
        return

    case_options = {
        f"{case[0]} — {case[1]}": case[0]
        for case in cases
    }

    selected_case = st.selectbox(
        "Select Investigation Case",
        list(case_options.keys()),
    )
    case_id = case_options[selected_case]

    col1, col2 = st.columns(2)

    with col1:
        evidence_type = st.selectbox(
            "Evidence Type",
            [
                "Digital Document",
                "Image",
                "Video",
                "Audio",
                "Archive",
                "System Artifact",
                "Other",
            ],
        )

    with col2:
        priority = st.selectbox(
            "Priority",
            ["Normal", "High", "Critical"],
        )

    source = st.text_input(
        "Evidence Source",
        placeholder="Example: Seized workstation / mobile device / email export",
    )

    tags = st.text_input(
        "Evidence Tags",
        placeholder="Example: fraud, transaction, suspect, email",
    )

    description = st.text_area(
        "Evidence Description",
        placeholder="Describe what this evidence represents and why it matters.",
    )

    uploaded_file = st.file_uploader(
        "Choose Evidence File",
        type=[
            "pdf", "txt", "doc", "docx",
            "jpg", "jpeg", "png",
            "mp3", "wav", "mp4",
            "zip", "csv", "json",
        ],
    )

    if uploaded_file:
        st.info(
            f"Selected: {uploaded_file.name} "
            f"• {uploaded_file.size:,} bytes"
        )

        if st.button(
            "Secure, Register & Index Evidence",
            use_container_width=True,
        ):
            try:
                document_id, document_hash = save_document_with_extensions(
                    uploaded_file,
                    case_id,
                    user["name"],
                )

                upsert_evidence_metadata(
                    document_id,
                    description,
                    tags,
                    source,
                    evidence_type,
                    priority,
                    "",
                    user["name"],
                )

                st.success("Evidence successfully registered and secured.")
                st.write(f"**Document ID:** `{document_id}`")
                st.write("**SHA-256 Fingerprint**")
                st.code(document_hash, language="text")
                st.write("**Security pipeline**")
                st.write(
                    "Original bytes → SHA-256 fingerprint → "
                    "AES-256-GCM encryption → encrypted vault → "
                    "audit ledger → semantic index"
                )
            except Exception as exc:
                st.error(f"Evidence registration failed: {exc}")


def enhanced_cases_page():
    st.title("Case Management")
    st.caption(
        "Investigation workspace, case ownership and collaboration."
    )

    user = st.session_state.user

    if role_permission(user, "can_create_case"):
        st.subheader("Create Investigation Case")

        title = st.text_input(
            "Case Title",
            placeholder="Example: Digital Fraud Investigation",
            key="new_case_title",
        )

        description = st.text_area(
            "Case Description",
            placeholder="Investigation scope, objective and context.",
            key="new_case_description",
        )

        if st.button(
            "Create Case",
            use_container_width=True,
            key="create_case_class3",
        ):
            if not title.strip():
                st.warning("Please enter a case title.")
            else:
                if HOSTED_STREAMLIT:
                    try:
                        case_id = create_case(
                            title,
                            description,
                            user["name"],
                        )
                        st.success(f"Case created: {case_id}")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Could not create case: {exc}")
                else:
                    try:
                        response = requests.post(
                            "http://127.0.0.1:8000/cases",
                            json={
                                "title": title,
                                "description": description,
                                "created_by": user["name"],
                            },
                            timeout=10,
                        )
                        data = response.json()
                    except requests.RequestException as exc:
                        st.error(f"Aurex API connection failed: {exc}")
                        data = {}
                        response = None
                    except ValueError:
                        st.error("Aurex API returned an invalid response.")
                        data = {}
                        response = None

                    if response is not None and response.status_code in (200, 201) and data.get("case_id"):
                        st.success(f"Case created: {data['case_id']}")
                        st.rerun()
                    elif response is not None:
                        st.error(
                            f"Could not create case. Backend returned "
                            f"{response.status_code}: {data.get('error', response.text)}"
                        )

    st.divider()
    st.subheader("Investigation Cases")

    # Local development can use the embedded FastAPI endpoint.
    # Community Cloud uses the same database/service layer directly because
    # the platform already owns the Streamlit server process.
    if HOSTED_STREAMLIT:
        cases = []
        for index, row in enumerate(get_cases(), start=1):
            cases.append({
                "id": index,
                "case_id": row[0],
                "title": row[1],
                "description": row[2],
                "created_by": row[3],
                "created_at": row[4],
            })
    else:
        try:
            response = requests.get(
                "http://127.0.0.1:8000/cases",
                timeout=10,
            )
            data = response.json()

            if response.status_code == 200:
                cases = data.get("cases", [])
            else:
                st.error(
                    f"Could not load cases from backend: "
                    f"{data.get('error', response.text)}"
                )
                cases = []
        except requests.RequestException as exc:
            st.error(f"Aurex API connection failed: {exc}")
            cases = []
        except ValueError:
            st.error("Aurex API returned an invalid response while loading cases.")
            cases = []

    if not cases:
        st.info("No cases created yet.")
        return

    all_users = get_all_users()
    user_options = {
        f"{row[1]} — {row[3]} — {row[2]}": row[2]
        for row in all_users
    }

    for case in cases:
        # FastAPI returns case objects as JSON dictionaries.
        # Keep the database id only for unique Streamlit widget keys.
        db_id = case.get("id")
        case_id = case.get("case_id", "")
        title = case.get("title", "")
        description = case.get("description", "")
        created_by = case.get("created_by", "")
        created_at = case.get("created_at", "")

        stats = get_case_statistics(case_id)

        with st.expander(
            f"{case_id} — {title}",
            expanded=False,
        ):
            st.write(
                description or "No description provided."
            )

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "Evidence",
                stats["documents"],
            )

            c2.metric(
                "Encrypted",
                stats["encrypted"],
            )

            c3.metric(
                "Verified",
                stats["verified"],
            )

            c4.metric(
                "Tamper Flags",
                stats["tampered"],
            )

            st.caption(
                f"Created by {created_by} • {created_at}"
            )

            st.divider()
            st.subheader("Collaborative Assignment")

            if role_permission(
                user,
                "can_manage_workflow",
            ):
                selected_member = st.selectbox(
                    "Assign investigator / analyst",
                    list(user_options.keys()),
                    key="assign_" + str(case_id) + "_" + str(db_id),
                )

                if st.button(
                    "Assign to Case",
                    key="assign_btn_" + case_id,
                ):
                    ok, message = assign_case_member(
                        case_id,
                        user_options[selected_member],
                        user["name"],
                    )

                    if ok:
                        record_compliance_event(
                            case_id,
                            "",
                            "COLLABORATION",
                            message,
                            user["name"],
                        )
                        st.success(message)
                    else:
                        st.error(message)

            members = get_case_members(case_id)

            if members:
                st.write("**Current Case Team**")

                for member in members:
                    st.write(
                        f"• {member[0]} — {member[1]} "
                        f"(assigned {member[2]})"
                    )
            else:
                st.caption(
                    "No additional case members assigned."
                )

            documents = get_case_documents(case_id)

            if documents:
                st.write("**Evidence in Case**")

                for document in documents:
                    workflow = get_workflow(document[0])
                    stage = (
                        workflow[1]
                        if workflow
                        else "Ingested"
                    )

                    st.write(
                        f"• `{document[0]}` — "
                        f"{document[2]} — {stage}"
                    )

def evidence_intelligence_page():
    st.title("Evidence Intelligence")
    st.caption(
        "Prototype AI Semantic Indexer: search evidence using "
        "case metadata, filenames, fingerprints, tags and notes."
    )

    documents = get_documents()

    if not documents:
        st.info("No evidence has been indexed yet.")
        return

    rebuild_all_semantic_indexes()

    query = st.text_input(
        "Search the Evidence Knowledge Index",
        placeholder="Try: fraud, email, transaction, suspect, device...",
    )

    if not query.strip():
        st.info(
            "Enter a concept or keyword to search across the indexed "
            "evidence metadata."
        )
        return

    results = semantic_search(query)

    st.write(
        f"**{len(results)} matching evidence item(s)**"
    )

    if not results:
        st.warning(
            "No matching evidence found. Try a broader term or add "
            "more evidence metadata."
        )
        return

    for item in results:
        document = item["document"]
        metadata = get_evidence_metadata(document[0])
        workflow = get_workflow(document[0])

        with st.container(border=True):
            st.subheader(document[2])
            st.caption(
                f"{document[0]} • Case {document[1]} • "
                f"Relevance score {item['score']}"
            )

            st.write(
                "**Matched concepts:** "
                + ", ".join(item["matched"])
            )

            c1, c2 = st.columns(2)

            with c1:
                st.write(f"**SHA-256:** `{document[3]}`")
                st.write(f"**Status:** {document[6]}")
                if metadata:
                    st.write(
                        f"**Tags:** {metadata[2] or 'None'}"
                    )
                    st.write(
                        f"**Source:** {metadata[3] or 'Not specified'}"
                    )

            with c2:
                if workflow:
                    st.write(
                        f"**Workflow:** {workflow[1]}"
                    )
                    st.write(
                        f"**Decision:** {workflow[4]}"
                    )
                st.write(
                    f"**Uploaded:** {document[5]}"
                )


def evidence_review_page():
    st.title("Forensic Review Workflow")
    st.caption(
        "Collaborative review, assignment, decision tracking and "
        "evidence lifecycle management."
    )

    user = st.session_state.user

    if not role_permission(user, "can_review"):
        st.warning(
            "Forensic review actions are restricted to the "
            "Forensic Analyst role in this prototype."
        )
        return

    documents = get_documents()

    if not documents:
        st.info("No evidence available for review.")
        return

    document_options = {
        f"{d[0]} — {d[2]}": d[0]
        for d in documents
    }

    selected = st.selectbox(
        "Select Evidence",
        list(document_options.keys()),
    )
    document_id = document_options[selected]
    document = get_document_record(document_id)

    ensure_workflow(document_id, user["name"])
    workflow = get_workflow(document_id)

    st.divider()

    c1, c2, c3 = st.columns(3)
    c1.metric("Current Stage", workflow[1])
    c2.metric("Decision", workflow[4])
    c3.metric("Evidence Status", document[7])

    assigned_to = st.text_input(
        "Assigned Analyst",
        value=workflow[2],
        placeholder="Analyst name or email",
    )

    reviewer = st.text_input(
        "Reviewer",
        value=workflow[3],
        placeholder="Reviewer name or email",
    )

    stage = st.selectbox(
        "Workflow Stage",
        [
            "Ingested",
            "Under Review",
            "Forensic Analysis",
            "Verified",
            "Escalated",
            "Approved",
            "Rejected",
            "Archived",
        ],
        index=[
            "Ingested",
            "Under Review",
            "Forensic Analysis",
            "Verified",
            "Escalated",
            "Approved",
            "Rejected",
            "Archived",
        ].index(workflow[1])
        if workflow[1] in [
            "Ingested",
            "Under Review",
            "Forensic Analysis",
            "Verified",
            "Escalated",
            "Approved",
            "Rejected",
            "Archived",
        ] else 0,
    )

    decision = st.selectbox(
        "Review Decision",
        ["Pending", "Verified", "Needs Further Analysis", "Approved", "Rejected"],
        index=[
            "Pending",
            "Verified",
            "Needs Further Analysis",
            "Approved",
            "Rejected",
        ].index(workflow[4])
        if workflow[4] in [
            "Pending",
            "Verified",
            "Needs Further Analysis",
            "Approved",
            "Rejected",
        ] else 0,
    )

    comments = st.text_area(
        "Forensic Review Notes",
        value=workflow[5],
        placeholder="Record findings, observations or review rationale.",
    )

    if st.button(
        "Save Review Decision",
        use_container_width=True,
    ):
        ok, message = update_workflow(
            document_id,
            stage,
            assigned_to,
            reviewer,
            decision,
            comments,
            user["name"],
        )

        if ok:
            if decision == "Verified":
                update_document_status(
                    document_id,
                    "Encrypted & Verified",
                    user["name"],
                )
            elif decision == "Rejected":
                update_document_status(
                    document_id,
                    "Review Rejected",
                    user["name"],
                )

            st.success(message)
        else:
            st.error(message)


def enhanced_vault_page():
    st.title("Evidence Vault")
    st.caption(
        "Encrypted evidence storage, integrity verification and "
        "zero-trust access decisions."
    )

    user = st.session_state.user
    attributes = get_user_attributes(user)

    st.success(
        "AES-256-GCM ENCRYPTION ACTIVE — Evidence encrypted at rest."
    )

    st.info(
        f"Access profile: **{attributes['role']}** • "
        f"Clearance: **{attributes['clearance']}** • "
        f"Protected access: "
        f"{'ENABLED' if attributes['protected_access'] else 'RESTRICTED'}"
    )

    documents = get_documents()

    if not documents:
        st.info("No evidence available.")
        return

    for document in documents:
        (
            document_id,
            case_id,
            filename,
            sha256_hash,
            uploaded_by,
            uploaded_at,
            status,
        ) = document

        metadata = get_evidence_metadata(document_id)
        workflow = get_workflow(document_id)

        with st.expander(
            f"{filename} — {document_id}",
            expanded=False,
        ):
            c1, c2 = st.columns(2)

            with c1:
                st.write(f"**Case:** {case_id}")
                st.write(f"**Uploaded by:** {uploaded_by}")
                st.write(f"**Uploaded:** {uploaded_at}")
                st.write(f"**Storage:** AES-256-GCM encrypted")
                st.write(f"**Status:** {status}")

                if metadata:
                    st.write(
                        f"**Type:** {metadata[4]} • "
                        f"**Priority:** {metadata[5]}"
                    )

            with c2:
                st.write("**SHA-256 Fingerprint**")
                st.code(sha256_hash, language="text")

                if workflow:
                    st.write(
                        f"**Workflow:** {workflow[1]} • "
                        f"**Decision:** {workflow[4]}"
                    )

            st.divider()

            if st.button(
                "Verify Integrity",
                key="verify_class3_" + document_id,
            ):
                result = verify_document(
                    document_id,
                    user["name"],
                )

                if result["valid"]:
                    update_document_status(
                        document_id,
                        "Encrypted & Verified",
                        user["name"],
                    )
                    st.success(
                        "INTEGRITY VERIFIED — SHA-256 matches the "
                        "registered fingerprint and AES-GCM authentication passed."
                    )
                else:
                    update_document_status(
                        document_id,
                        "TAMPER DETECTED",
                        user["name"],
                    )
                    st.error(
                        "TAMPERING DETECTED — cryptographic verification failed."
                    )

                st.write("**Registered Hash**")
                st.code(result["original_hash"])
                st.write("**Current Hash**")
                st.code(result["current_hash"])

            st.divider()
            st.subheader("Zero-Trust Protected Access")

            if attributes["protected_access"]:
                if st.button(
                    "Request Protected Access",
                    key="request_class3_" + document_id,
                ):
                    result = request_protected_document(
                        document_id,
                        user,
                    )

                    decision = "GRANTED" if result["success"] else "DENIED"
                    record_access_request(
                        document_id,
                        user,
                        decision,
                        result["reason"],
                    )

                    if result["success"]:
                        access_key = "vault_access_" + document_id
                        filename_key = access_key + "_filename"
                        st.session_state[access_key] = result["data"]
                        st.session_state[filename_key] = result["filename"]

                        st.success(
                            "ACCESS GRANTED — identity, role and "
                            "protected-access attributes satisfied."
                        )
                    else:
                        st.error(result["reason"])

                access_key = "vault_access_" + document_id
                filename_key = access_key + "_filename"

                if access_key in st.session_state:
                    mime_type = mimetypes.guess_type(
                        st.session_state[filename_key]
                    )[0] or "application/octet-stream"

                    st.download_button(
                        "Download Authorized Evidence",
                        data=st.session_state[access_key],
                        file_name=st.session_state[filename_key],
                        mime=mime_type,
                        key="download_class3_" + document_id,
                    )
            else:
                if st.button(
                    "Request Protected Access",
                    key="denied_class3_" + document_id,
                ):
                    result = request_protected_document(
                        document_id,
                        user,
                    )
                    record_access_request(
                        document_id,
                        user,
                        "DENIED",
                        result["reason"],
                    )
                    st.error(
                        "ACCESS DENIED — " + result["reason"]
                    )
                    st.warning(
                        "The denied request has been recorded in "
                        "the chain-of-custody trail."
                    )


def enhanced_chain_page():
    st.title("Chain of Custody")
    st.caption(
        "Hash-linked evidence activity ledger with independent "
        "integrity verification."
    )

    chain = verify_audit_chain()

    if chain["valid"]:
        st.success(
            f"AUDIT LEDGER VERIFIED — {chain['events']} event(s) checked."
        )
    else:
        st.error("AUDIT LEDGER INTEGRITY FAILURE.")
        for failure in chain["failures"]:
            st.write("• " + failure)

    logs = get_audit_logs()

    if not logs:
        st.info("No audit events recorded.")
        return

    st.divider()

    for log in logs:
        (
            document_id,
            case_id,
            action,
            performed_by,
            timestamp,
            previous_hash,
            event_hash,
        ) = log

        with st.container(border=True):
            st.markdown(f"### {action}")

            c1, c2 = st.columns(2)

            with c1:
                st.write(f"**Document:** `{document_id}`")
                st.write(f"**Case:** `{case_id}`")
                st.write(f"**Officer:** {performed_by}")
                st.write(f"**Time:** {timestamp}")

            with c2:
                st.write("**Previous Hash**")
                st.code(previous_hash or "GENESIS")
                st.write("**Event Hash**")
                st.code(event_hash)


def compliance_gateway_page():
    st.title("Compliance & Forensic Gateway")
    st.caption(
        "Case-level compliance monitoring, audit verification and "
        "court-ready prototype reporting."
    )

    user = st.session_state.user
    cases = get_cases()

    if not cases:
        st.info("Create a case before using the compliance gateway.")
        return

    case_options = {
        f"{case[0]} — {case[1]}": case[0]
        for case in cases
    }

    selected = st.selectbox(
        "Select Case",
        list(case_options.keys()),
    )
    case_id = case_options[selected]
    case = get_case_record(case_id)
    stats = get_case_statistics(case_id)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Evidence", stats["documents"])
    c2.metric("Encrypted", stats["encrypted"])
    c3.metric("Verified", stats["verified"])
    c4.metric("Tamper Flags", stats["tampered"])

    st.divider()

    st.subheader("Compliance Checklist")

    documents = get_documents(case_id)
    checklist = []

    checklist.append(
        ("Case registered", bool(case))
    )
    checklist.append(
        ("Evidence inventory recorded", len(documents) > 0)
    )
    checklist.append(
        ("All evidence has SHA-256 fingerprints",
         all(len(d[3]) == 64 for d in documents) if documents else False)
    )
    checklist.append(
        ("Evidence stored encrypted",
         all("Encrypted" in (d[6] or "") for d in documents)
         if documents else False)
    )
    checklist.append(
        ("Audit ledger hash chain valid",
         verify_audit_chain()["valid"])
    )

    for label, passed in checklist:
        if passed:
            st.success("PASS — " + label)
        else:
            st.warning("ACTION REQUIRED — " + label)

    st.divider()

    st.subheader("Compliance Event Stream")
    events = get_compliance_events(case_id)

    if events:
        for event in events:
            with st.container(border=True):
                st.write(
                    f"**{event[2]}** • {event[5]} • {event[4]}"
                )
                st.caption(
                    f"Document: {event[1] or 'N/A'}"
                )
                st.write(event[3])
    else:
        st.info("No compliance events recorded for this case.")

    st.divider()

    st.subheader("Court-Ready Case Report")

    report = build_case_report(case_id)

    if st.button(
        "Generate Case Report",
        use_container_width=True,
    ):
        record_compliance_event(
            case_id,
            "",
            "REPORT",
            "Court-ready prototype case report generated.",
            user["name"],
        )
        add_audit_log(
            "CASE-" + case_id,
            case_id,
            "CASE REPORT GENERATED",
            user["name"],
        )
        st.success("Case report generated.")

    if report:
        st.download_button(
            "Download Case Report",
            data=report.encode("utf-8"),
            file_name=f"{case_id}_Aurex_Case_Report.txt",
            mime="text/plain",
            use_container_width=True,
        )

        with st.expander("Preview Report"):
            st.code(report, language="text")


def enhanced_certificate_page():
    st.title("Evidence Integrity Certificate")
    st.caption(
        "Generate a cryptographic record of an evidence item and "
        "its current verification state."
    )

    documents = get_documents()

    if not documents:
        st.info("No evidence available.")
        return

    user = st.session_state.user

    document_options = {
        f"{d[0]} — {d[2]}": d[0]
        for d in documents
    }

    selected = st.selectbox(
        "Select Evidence",
        list(document_options.keys()),
    )
    document_id = document_options[selected]
    document = get_document_record(document_id)
    workflow = get_workflow(document_id)
    metadata = get_evidence_metadata(document_id)

    if st.button(
        "Verify & Generate Integrity Certificate",
        use_container_width=True,
    ):
        result = verify_document(
            document_id,
            user["name"],
        )

        certificate_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        if result["valid"]:
            certificate_status = "CRYPTOGRAPHICALLY VERIFIED"
            st.success(certificate_status)
        else:
            certificate_status = "VERIFICATION FAILED"
            st.error(certificate_status)

        report = [
            "AUREX",
            "DIGITAL EVIDENCE INTEGRITY CERTIFICATE",
            "=" * 68,
            "",
            f"Certificate Status: {certificate_status}",
            f"Document ID: {document[0]}",
            f"Case ID: {document[1]}",
            f"Evidence File: {document[2]}",
            f"Registered By: {document[5]}",
            f"Original Registration: {document[6]}",
            f"Verification Time: {certificate_time}",
            "",
            "CRYPTOGRAPHIC IDENTITY",
            "-" * 68,
            f"Registered SHA-256: {result['original_hash']}",
            f"Current SHA-256:    {result['current_hash']}",
            "",
            "SECURITY CONTROLS",
            "-" * 68,
            "AES-256-GCM encrypted at rest",
            "SHA-256 evidence fingerprint",
            "Hash-linked chain-of-custody audit",
            "Role / attribute-based access decision",
        ]

        if metadata:
            report.extend([
                "",
                "EVIDENCE METADATA",
                "-" * 68,
                f"Type: {metadata[4]}",
                f"Priority: {metadata[5]}",
                f"Tags: {metadata[2] or 'None'}",
                f"Source: {metadata[3] or 'Not specified'}",
                f"Description: {metadata[1] or 'Not specified'}",
            ])

        if workflow:
            report.extend([
                "",
                "WORKFLOW",
                "-" * 68,
                f"Stage: {workflow[1]}",
                f"Assigned To: {workflow[2] or 'Unassigned'}",
                f"Reviewer: {workflow[3] or 'Unassigned'}",
                f"Decision: {workflow[4]}",
                f"Comments: {workflow[5] or 'None'}",
            ])

        report.extend([
            "",
            "AUREX PROTOTYPE NOTICE",
            "-" * 68,
            "This certificate demonstrates the prototype workflow.",
            "Production deployment would add digital signatures,",
            "HSM/KMS-backed key management and a permissioned ledger.",
        ])

        record_compliance_event(
            document[1],
            document_id,
            "CERTIFICATE",
            "Integrity certificate generated.",
            user["name"],
        )

        st.download_button(
            "Download Integrity Certificate",
            data="\n".join(report).encode("utf-8"),
            file_name=f"{document_id}_Integrity_Certificate.txt",
            mime="text/plain",
            use_container_width=True,
        )


def delete_evidence_local(document_id):
    """Delete one evidence record and its prototype records/files locally."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT document_id, case_id, file_path
        FROM documents
        WHERE document_id = ?
    """, (document_id,))

    row = cursor.fetchone()
    if row is None:
        connection.close()
        return False

    stored_document_id, case_id, file_path = row

    for table, column in [
        ("evidence_metadata", "document_id"),
        ("workflow", "document_id"),
        ("access_requests", "document_id"),
        ("semantic_index", "document_id"),
    ]:
        try:
            cursor.execute(
                f"DELETE FROM {table} WHERE {column} = ?",
                (stored_document_id,),
            )
        except sqlite3.OperationalError:
            pass

    try:
        cursor.execute(
            "DELETE FROM compliance_events WHERE document_id = ?",
            (stored_document_id,),
        )
    except sqlite3.OperationalError:
        pass

    cursor.execute(
        "DELETE FROM audit_logs WHERE document_id = ?",
        (stored_document_id,),
    )
    cursor.execute(
        "DELETE FROM documents WHERE document_id = ?",
        (stored_document_id,),
    )

    cursor.execute("SELECT COUNT(*) FROM documents")
    remaining_documents = cursor.fetchone()[0]
    if remaining_documents == 0:
        cursor.execute("DELETE FROM audit_logs")

    connection.commit()
    connection.close()

    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass

    return True


def delete_case_local(case_id):
    """Delete a case and all prototype data belonging to it locally."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT document_id, file_path FROM documents WHERE case_id = ?",
        (case_id,),
    )
    documents = cursor.fetchall()

    cursor.execute(
        "SELECT id FROM cases WHERE case_id = ?",
        (case_id,),
    )
    case_row = cursor.fetchone()

    if case_row is None:
        connection.close()
        return False

    document_ids = [row[0] for row in documents]
    file_paths = [row[1] for row in documents if row[1]]

    for table, column in [
        ("evidence_metadata", "document_id"),
        ("workflow", "document_id"),
        ("access_requests", "document_id"),
        ("semantic_index", "document_id"),
    ]:
        try:
            for document_id in document_ids:
                cursor.execute(
                    f"DELETE FROM {table} WHERE {column} = ?",
                    (document_id,),
                )
        except sqlite3.OperationalError:
            pass

    try:
        cursor.execute(
            "DELETE FROM compliance_events WHERE case_id = ?",
            (case_id,),
        )
    except sqlite3.OperationalError:
        pass

    cursor.execute("DELETE FROM audit_logs WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM documents WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM case_members WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))

    connection.commit()
    connection.close()

    for file_path in file_paths:
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

    return True


def enhanced_dashboard_page():
    st.title("Aurex Command Center")

    user = st.session_state.user
    st.caption(
        f"{user['name']} • {user['role']} • "
        f"{get_user_attributes(user)['clearance']} clearance"
    )

    cases = get_cases()
    documents = get_documents()
    logs = get_audit_logs()

    verified_count = sum(
        1 for d in documents if "Verified" in (d[6] or "")
    )
    tampered_count = sum(
        1 for d in documents if "Tamper" in (d[6] or "")
    )
    encrypted_count = sum(
        1 for d in documents if "Encrypted" in (d[6] or "")
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Active Cases", len(cases))
    c2.metric("Evidence Files", len(documents))
    c3.metric("Encrypted", encrypted_count)
    c4.metric("Verified", verified_count)
    c5.metric("Audit Events", len(logs))

    # --------------------------------------------------------
    # PROTOTYPE DEMO RESET
    # --------------------------------------------------------
    if role_permission(user, "can_manage_workflow"):
        with st.expander("Prototype Data Reset"):
            st.warning(
                "Use these controls only to reset demo data. "
                "They permanently remove prototype cases/evidence "
                "from the local database and encrypted vault."
            )

            r1, r2 = st.columns(2)

            with r1:
                if st.button(
                    "Delete All Documents",
                    use_container_width=True,
                    key="reset_all_documents",
                ):
                    if HOSTED_STREAMLIT:
                        evidence = get_documents()
                        deleted = sum(
                            1
                            for item in evidence
                            if delete_evidence_local(item[0])
                        )
                        st.success(f"Deleted {deleted} evidence file(s).")
                        st.rerun()
                    else:
                        try:
                            response = requests.get(
                                "http://127.0.0.1:8000/evidence",
                                timeout=10,
                            )
                            data = response.json()

                            if response.status_code != 200:
                                st.error(
                                    "Could not load evidence from backend."
                                )
                            else:
                                evidence = data.get("evidence", [])
                                failures = []

                                for item in evidence:
                                    document_id = item.get("document_id")
                                    delete_response = requests.delete(
                                        "http://127.0.0.1:8000/evidence/"
                                        + str(document_id),
                                        timeout=10,
                                    )

                                    if delete_response.status_code != 200:
                                        failures.append(document_id)

                                if failures:
                                    st.error(
                                        "Some evidence could not be deleted: "
                                        + ", ".join(map(str, failures))
                                    )
                                else:
                                    st.success(
                                        f"Deleted {len(evidence)} evidence file(s)."
                                    )
                                    st.rerun()

                        except (requests.RequestException, ValueError) as exc:
                            st.error(
                                f"Aurex API reset failed: {exc}"
                            )

            with r2:
                if st.button(
                    "Delete All Cases",
                    use_container_width=True,
                    key="reset_all_cases",
                ):
                    if HOSTED_STREAMLIT:
                        existing_cases = get_cases()
                        deleted = sum(
                            1
                            for item in existing_cases
                            if delete_case_local(item[0])
                        )
                        st.success(f"Deleted {deleted} case(s).")
                        st.rerun()
                    else:
                        try:
                            response = requests.get(
                                "http://127.0.0.1:8000/cases",
                                timeout=10,
                            )
                            data = response.json()

                            if response.status_code != 200:
                                st.error(
                                    "Could not load cases from backend."
                                )
                            else:
                                existing_cases = data.get("cases", [])
                                failures = []

                                for item in existing_cases:
                                    case_id = item.get("case_id")
                                    delete_response = requests.delete(
                                        "http://127.0.0.1:8000/cases/"
                                        + str(case_id),
                                        timeout=10,
                                    )

                                    if delete_response.status_code != 200:
                                        failures.append(case_id)

                                if failures:
                                    st.error(
                                        "Some cases could not be deleted: "
                                        + ", ".join(map(str, failures))
                                    )
                                else:
                                    st.success(
                                        f"Deleted {len(existing_cases)} case(s)."
                                    )
                                    st.rerun()

                        except (requests.RequestException, ValueError) as exc:
                            st.error(
                                f"Aurex API reset failed: {exc}"
                            )

    st.divider()

    chain = verify_audit_chain()

    c1, c2, c3 = st.columns(3)

    with c1:
        if tampered_count == 0:
            st.success("EVIDENCE INTEGRITY HEALTHY")
        else:
            st.error(f"{tampered_count} TAMPER FLAG(S)")
        st.caption(
            "SHA-256 fingerprints are used as the evidence identity."
        )

    with c2:
        if chain["valid"]:
            st.success("AUDIT LEDGER VERIFIED")
        else:
            st.error("AUDIT LEDGER ALERT")
        st.caption(
            f"{chain['events']} hash-linked event(s) checked."
        )

    with c3:
        st.success("ZERO-TRUST VAULT ACTIVE")
        st.caption(
            "AES-256-GCM encryption plus role/attribute decisions."
        )

    st.divider()

    st.subheader("Aurex Security Pipeline")

    st.markdown(
        """
        **1. Identity** → authenticated user and role

        ↓

        **2. Case Context** → evidence belongs to a controlled case

        ↓

        **3. Evidence Ingestion** → fingerprint + metadata

        ↓

        **4. Zero-Trust Vault** → AES-256-GCM encrypted storage

        ↓

        **5. Integrity Verification** → SHA-256 + authenticated decryption

        ↓

        **6. Workflow Engine** → assignment, review and decisions

        ↓

        **7. Immutable-Style Ledger** → hash-linked chain of custody

        ↓

        **8. Compliance Gateway** → reports and audit validation
        """
    )

    st.divider()
    st.subheader("Recent Evidence")

    if documents:
        for document in documents[:5]:
            with st.container(border=True):
                st.write(
                    f"**{document[2]}** — `{document[0]}`"
                )
                st.caption(
                    f"Case {document[1]} • "
                    f"{document[4]} • {document[5]}"
                )
                st.write(f"Status: **{document[6]}**")
    else:
        st.info("No evidence uploaded yet.")


def enhanced_architecture_page():
    st.title("Aurex Architecture")
    st.caption(
        "Prototype architecture aligned with the intended Aurex platform."
    )

    st.subheader("Five Core Aurex Abstractions")

    architecture = [
        (
            "1. Zero-Trust Document Vault",
            "Encrypted evidence at rest, cryptographic identity and "
            "attribute-based access decisions.",
        ),
        (
            "2. Immutable Audit Ledger",
            "Every significant evidence event is hash-linked to the "
            "previous event to demonstrate tamper-evident custody.",
        ),
        (
            "3. AI Semantic Indexer",
            "Prototype semantic search across evidence filenames, case "
            "context, metadata, tags and analyst notes. A real embedding "
            "model can replace this layer later.",
        ),
        (
            "4. Collaborative Workflow Engine",
            "Case assignment, forensic review stages, reviewers, "
            "decisions and comments.",
        ),
        (
            "5. Compliance & Forensic Gateway",
            "Integrity checks, compliance checklist, audit validation, "
            "certificates and court-ready case reports.",
        ),
    ]

    for title, description in architecture:
        with st.container(border=True):
            st.subheader(title)
            st.write(description)

    st.divider()

    st.subheader("Current Prototype Stack")

    stack = [
        ("Frontend", "Streamlit"),
        ("API Layer", "FastAPI-ready service boundary (separate backend)"),
        ("Application State", "Python"),
        ("Database", "SQLite"),
        ("Integrity", "SHA-256"),
        ("Encryption", "AES-256-GCM"),
        ("Access Control", "Role + attribute-based prototype policy"),
        ("Audit", "Hash-linked SQLite ledger"),
        ("Semantic Search", "Local prototype token/scoring index"),
        ("Reports", "Generated text certificates and case reports"),
    ]

    for component, implementation in stack:
        st.write(f"**{component}:** {implementation}")

    st.divider()

    st.subheader("Production Evolution")

    st.markdown(
        """
        **Streamlit UI**
        → **FastAPI API layer**
        → Authentication / RBAC / ABAC
        → Evidence service
        → Object storage
        → HSM/KMS-backed key management
        → Semantic/vector index
        → Workflow service
        → Permissioned ledger
        → Compliance and reporting services
        """
    )

    st.warning(
        "Prototype boundary: the current application runs Streamlit and "
        "FastAPI in the same local process. SQLite and encrypted local "
        "storage are used for the hackathon prototype. Production Aurex "
        "would separate services and add HSM/KMS-backed keys, object "
        "storage, digital signatures and a permissioned ledger."
    )


def enhanced_logout():
    clear_vault_session_data()

    st.session_state.logged_in = False
    st.session_state.user = None

    # Remove page-specific state that may contain sensitive selections.
    for key in [
        "selected_case",
        "selected_document",
    ]:
        if key in st.session_state:
            del st.session_state[key]

    st.rerun()



# ============================================================
# API NOTE
# ============================================================
# The previous prototype embedded Uvicorn/FastAPI in this same process.
# That caused the local port to sometimes serve the API JSON instead of
# Streamlit. The full UI prototype is preserved, but the API listener is
# intentionally disabled for the presentation build. A separate backend.py
# can expose the API later without changing this UI.


# ============================================================
# MAIN
# ============================================================

def main():

    st.set_page_config(
        page_title="Aurex",
        page_icon="◈",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    apply_aurex_design()

    initialize_database()
    initialize_extended_database()
    initialize_session()

    if not st.session_state.logged_in:
        login_page()
        return

    user = st.session_state.user

    st.sidebar.markdown("## ◈ AUREX")
    st.sidebar.caption("SECURE EVIDENCE PLATFORM")

    st.sidebar.divider()

    st.sidebar.write(
        f"**User**  \n{user['name']}"
    )
    st.sidebar.write(
        f"**Role**  \n{user['role']}"
    )

    st.sidebar.divider()

    page = st.sidebar.radio(
        "WORKSPACE",
        [
            "Dashboard",
            "Cases",
            "Upload Evidence",
            "Evidence Vault",
            "Evidence Intelligence",
            "Forensic Review",
            "Chain of Custody",
            "Compliance Gateway",
            "Integrity Certificate",
            "Architecture",
        ],
    )

    st.sidebar.divider()

    attributes = get_user_attributes(user)

    st.sidebar.success("SYSTEM ONLINE")

    st.sidebar.caption(
        f"Clearance: {attributes['clearance']}"
    )

    st.sidebar.caption(
        "Prototype Environment • Class 3"
    )

    st.sidebar.divider()

    if st.sidebar.button(
        "Logout",
        use_container_width=True,
    ):
        enhanced_logout()

    if page == "Dashboard":
        enhanced_dashboard_page()

    elif page == "Cases":
        enhanced_cases_page()

    elif page == "Upload Evidence":
        enhanced_upload_page()

    elif page == "Evidence Vault":
        enhanced_vault_page()

    elif page == "Evidence Intelligence":
        evidence_intelligence_page()

    elif page == "Forensic Review":
        evidence_review_page()

    elif page == "Chain of Custody":
        enhanced_chain_page()

    elif page == "Compliance Gateway":
        compliance_gateway_page()

    elif page == "Integrity Certificate":
        enhanced_certificate_page()

    elif page == "Architecture":
        enhanced_architecture_page()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()
