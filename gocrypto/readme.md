# Crypto Toolkit — Python + Streamlit

A browser-based Python rewrite of the uploaded Go cryptography toolkit's main user-facing capabilities.

## Features
- File encryption and decryption using AES-256-GCM.
- Text encryption and decryption using the same authenticated format (Base64 for sharing).
- SHA-256, SHA3-256, SHA-512 and SHA3-512 hashes.
- Cryptographically secure random password generation.
- Downloadable encrypted/decrypted files and hash output.

## Run locally
Python 3.10 or newer is recommended.

```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Create a new GitHub repository.
2. Upload `app.py`, `requirements.txt`, and `README.md` to the repository root.
3. Sign in at https://share.streamlit.io/ using GitHub.
4. Select **Create app**, choose the repository and branch, and set the main file path to `app.py`.
5. Deploy.

No API keys or secrets are required.

## Encryption format and compatibility
This is a clean Python implementation of the main features, not a byte-for-byte port of the original Go cipher internals. It uses AES-256-GCM with a random 16-byte salt, random 12-byte nonce, and PBKDF2-HMAC-SHA256 (600,000 iterations). The format is versioned with a short header. It cannot decrypt files created by the original Go application, and the original Go application cannot decrypt files created here.

## Security
- Use a long, unique password (the app requires at least 8 characters; 12+ is recommended).
- There is no password reset or recovery mechanism.
- Keep an independent backup of important original files.
- Hashing is one-way and is not encryption.
- This app does not store uploaded files or passwords in a database. As with any hosted app, do not upload highly sensitive material unless you trust the hosting environment and have reviewed its privacy/security characteristics.

## Project structure

```text
crypto_streamlit/
├── app.py
├── requirements.txt
└── README.md
```
