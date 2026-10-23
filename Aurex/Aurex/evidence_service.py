import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from database import get_connection


# ============================================================
# VAULT KEY
# ============================================================

VAULT_KEY_FILE = "aurex_vault.key"


def get_vault_key():
    with open(VAULT_KEY_FILE, "rb") as key_file:
        return key_file.read()


# ============================================================
# GET DOCUMENT RECORD
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


# ============================================================
# DECRYPT EVIDENCE
# ============================================================

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


# ============================================================
# VERIFY EVIDENCE
# ============================================================

def verify_document(document_id, user_name):
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

        if valid:
            action = "INTEGRITY VERIFIED"
        else:
            action = "TAMPER DETECTED"

    except Exception:
        valid = False
        current_hash = "DECRYPTION FAILED / FILE TAMPERED"
        action = "TAMPER DETECTED"

    return {
        "valid": valid,
        "case_id": case_id,
        "filename": filename,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "action": action,
        "verified_by": user_name
    }