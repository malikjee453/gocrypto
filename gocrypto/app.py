import base64
import hashlib
import secrets
import string
from pathlib import Path

import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "Crypto Toolkit"
MAGIC = b"PYCRYPTO1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Please enter a password.")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=KEY_SIZE
    )


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt bytes using AES-256-GCM and a password-derived key."""
    if not data:
        raise ValueError("There is no data to encrypt.")
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt a file produced by encrypt_bytes."""
    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE
    if len(blob) <= header_size or not blob.startswith(MAGIC):
        raise ValueError("This file is not a supported Crypto Toolkit encrypted file.")
    pos = len(MAGIC)
    salt = blob[pos:pos + SALT_SIZE]
    pos += SALT_SIZE
    nonce = blob[pos:pos + NONCE_SIZE]
    ciphertext = blob[pos + NONCE_SIZE:]
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except Exception as exc:
        raise ValueError("Decryption failed. The password may be incorrect or the file may be damaged.") from exc


def safe_output_name(name: str, suffix: str) -> str:
    base = Path(name).name
    return base + suffix


def password_generator(length: int, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


st.set_page_config(page_title=APP_NAME, page_icon="🔐", layout="wide")

st.markdown("""
<style>
    .block-container {padding-top: 1.6rem; padding-bottom: 2.5rem; max-width: 1150px;}
    .hero {padding: 1.35rem 1.5rem; border-radius: 16px;
           background: linear-gradient(120deg, rgba(59,130,246,.13), rgba(16,185,129,.10));
           border: 1px solid rgba(128,128,128,.18); margin-bottom: 1.2rem;}
    .hero h1 {margin: 0 0 .35rem 0; font-size: 2rem;}
    .muted {opacity: .75; font-size: .95rem;}
    div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.18);
        padding: 12px; border-radius: 12px;}
</style>
<div class="hero">
  <h1>🔐 Crypto Toolkit</h1>
  <div class="muted">A simple toolkit for protecting files, encrypting text, and checking file hashes.</div>
</div>
""", unsafe_allow_html=True)

st.caption("Python + Streamlit | AES-256-GCM authenticated encryption")

with st.sidebar:
    st.subheader("About")
    st.write("Encrypt and decrypt your own files and messages, calculate hashes, and generate strong passwords.")
    st.divider()
    st.markdown("**Security notes**")
    st.caption("Use a strong, unique password. If you lose it, encrypted data cannot be recovered.")
    st.caption("Passwords are used in memory for the current operation and are not saved by this app.")

tab_file, tab_text, tab_hash, tab_password = st.tabs(
    ["📁 File encryption", "💬 Text encryption", "#️⃣ Hash calculator", "🎲 Password generator"]
)

with tab_file:
    st.subheader("Protect a file")
    mode = st.radio("Choose operation", ["Encrypt file", "Decrypt file"], horizontal=True, key="file_mode")
    uploaded = st.file_uploader("Choose a file", key="file_upload")
    password = st.text_input("Password", type="password", key="file_password")
    if mode == "Encrypt file":
        confirm = st.text_input("Confirm password", type="password", key="file_confirm")
        if st.button("Encrypt file", type="primary", disabled=uploaded is None):
            if not password:
                st.error("Enter a password.")
            elif len(password) < 8:
                st.error("Use a password of at least 8 characters.")
            elif password != confirm:
                st.error("The passwords do not match.")
            else:
                try:
                    result = encrypt_bytes(uploaded.getvalue(), password)
                    filename = safe_output_name(uploaded.name, ".enc")
                    st.success("File encrypted successfully.")
                    st.download_button("⬇️ Download encrypted file", result, file_name=filename,
                                       mime="application/octet-stream")
                except Exception as e:
                    st.error(str(e))
    else:
        if st.button("Decrypt file", type="primary", disabled=uploaded is None):
            if not password:
                st.error("Enter the password used for encryption.")
            else:
                try:
                    result = decrypt_bytes(uploaded.getvalue(), password)
                    original = uploaded.name[:-4] if uploaded.name.endswith(".enc") else uploaded.name + ".decrypted"
                    st.success("File decrypted successfully.")
                    st.download_button("⬇️ Download decrypted file", result, file_name=original,
                                       mime="application/octet-stream")
                except ValueError as e:
                    st.error(str(e))

    st.info("The encrypted output includes a version marker, random salt, nonce, and authenticated ciphertext. Keep the password safe.")

with tab_text:
    st.subheader("Encrypt or decrypt a message")
    text_mode = st.radio("Operation", ["Encrypt text", "Decrypt text"], horizontal=True, key="text_mode")
    text_password = st.text_input("Text password", type="password", key="text_password")
    if text_mode == "Encrypt text":
        plain = st.text_area("Message to encrypt", height=150, placeholder="Type your message...")
        confirm_text = st.text_input("Confirm text password", type="password", key="text_confirm")
        if st.button("Encrypt message", type="primary"):
            if not plain:
                st.warning("Enter a message first.")
            elif len(text_password) < 8:
                st.error("Use a password of at least 8 characters.")
            elif text_password != confirm_text:
                st.error("The passwords do not match.")
            else:
                try:
                    encrypted = encrypt_bytes(plain.encode("utf-8"), text_password)
                    encoded = base64.urlsafe_b64encode(encrypted).decode("ascii")
                    st.success("Message encrypted.")
                    st.text_area("Encrypted message (Base64)", value=encoded, height=150)
                    st.download_button("Download encrypted text", encoded, file_name="encrypted_message.txt",
                                       mime="text/plain")
                except Exception as e:
                    st.error(str(e))
    else:
        encoded = st.text_area("Paste encrypted Base64 message", height=150)
        if st.button("Decrypt message", type="primary"):
            if not encoded.strip() or not text_password:
                st.error("Enter both the encrypted message and password.")
            else:
                try:
                    raw = base64.urlsafe_b64decode(encoded.strip().encode("ascii"))
                    decrypted = decrypt_bytes(raw, text_password).decode("utf-8")
                    st.success("Message decrypted.")
                    st.text_area("Decrypted message", value=decrypted, height=150)
                except Exception:
                    st.error("Could not decrypt. Check the password and make sure the encrypted text is complete.")

with tab_hash:
    st.subheader("Calculate a cryptographic hash")
    hash_file = st.file_uploader("Upload a file to hash", key="hash_upload")
    hash_text = st.text_area("Or enter text to hash", height=100)
    algorithm = st.selectbox("Hash algorithm", ["SHA-256", "SHA3-256", "SHA-512", "SHA3-512"])
    if st.button("Calculate hash", type="primary"):
        if hash_file is not None:
            data = hash_file.getvalue()
            source = f"File: {hash_file.name}"
        elif hash_text:
            data = hash_text.encode("utf-8")
            source = "Text input"
        else:
            data = None
            source = ""
        if data is None:
            st.warning("Upload a file or enter text.")
        else:
            hash_name = {"SHA-256": "sha256", "SHA3-256": "sha3_256", "SHA-512": "sha512", "SHA3-512": "sha3_512"}[algorithm]
            digest = hashlib.new(hash_name, data).hexdigest()
            st.write(source)
            st.code(digest, language=None)
            st.download_button("Download hash", digest, file_name="sha_hash.txt", mime="text/plain")
            st.caption("A hash is a one-way fingerprint; it does not encrypt or conceal the original data.")

with tab_password:
    st.subheader("Generate a strong random password")
    length = st.slider("Password length", min_value=12, max_value=64, value=24)
    symbols = st.checkbox("Include symbols", value=True)
    if st.button("Generate password", type="primary"):
        st.session_state.generated_password = password_generator(length, symbols)
    if st.session_state.get("generated_password"):
        st.code(st.session_state.generated_password, language=None)
        st.button("Copying is supported by selecting the password above.", disabled=True)
        st.caption("Generate a new password whenever you need another one.")

st.divider()
st.caption("This Python edition uses its own encrypted-file format and is not compatible with files encrypted by the original Go project.")
