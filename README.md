# AUREX — Digital Evidence Security Platform

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://fxalxyktvcfu62bobl3x6z.streamlit.app/)

**Protect • Verify • Trace**

AUREX is a digital evidence security platform designed to support secure evidence management, encryption, integrity verification, controlled access, and audit-ready chain of custody.

## 🚀 Live Demo

**Access the deployed application:**  
https://fxalxyktvcfu62bobl3x6z.streamlit.app/

## ✨ Key Features

- **Secure Evidence Management:** Manage digital evidence through a centralized application.
- **Encryption:** AES-GCM-based encryption for protecting digital data.
- **Integrity Verification:** Cryptographic hashing to help verify evidence integrity.
- **Controlled Access:** Workspace selection for different professional roles.
- **Chain of Custody:** Support for recording and tracking evidence-handling activities.
- **Database Integration:** SQLite-based data storage.
- **Interactive Interface:** Built with Streamlit.

## 🛠️ Technology Stack

- Python
- Streamlit
- SQLite
- Cryptography
- Hashlib

## 📁 Project Structure

```text
Aurex/
├── Aurex.py
├── backend.py
├── database.py
├── evidence_service.py
├── requirements.txt
├── README.md
└── .gitignore
```

*The directory structure above is illustrative; actual file locations may differ.*

## 💻 Run Locally

1. Clone this repository:

   ```bash
   git clone https://github.com/ishitawizard/aurex.git
   ```

2. Navigate to the project directory and install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the main Streamlit application using the correct path to `Aurex.py`:

   ```bash
   streamlit run Aurex.py
   ```

## 🔐 Security Notice

This project concerns digital evidence security. Do not publish confidential evidence, real user data, database files containing sensitive information, encryption keys, or credentials in a public repository.

## 🎯 Project Objective

To demonstrate how digital evidence can be managed with a focus on confidentiality, integrity, access control, and traceability.

## 📄 License

A license can be added to specify the terms under which this project may be used or distributed.
