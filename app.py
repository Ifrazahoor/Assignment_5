import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet

# --- Initialize Fernet Key and Cipher ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- In-Memory Data Store ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {data_id: {"encrypted_text": ..., "passkey": ...}}

# --- Session State for Failed Attempts ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Function to Hash Passkey ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Encrypt Data ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --- Decrypt Data ---
def decrypt_data(data_id, passkey):
    stored = st.session_state.stored_data.get(data_id)
    if not stored:
        return None

    hashed = hash_passkey(passkey)
    if stored["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(stored["encrypted_text"].encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# --- Streamlit UI ---
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔍 Navigate", menu)

# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve your secret data using a unique passkey!")

# --- Store Data ---
elif choice == "Store Data":
    st.subheader("📂 Store Secure Data")
    data_id = st.text_input("Enter a unique ID:")
    user_text = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data_id and user_text and passkey:
            encrypted = encrypt_data(user_text)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ All fields are required!")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Secure Data")
    data_id = st.text_input("Enter your Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            result = decrypt_data(data_id, passkey)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ All fields are required!")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔑 Login to Reauthorize")
    master = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master == "admin123":  # Use env vars or secret manager in real apps
            st.session_state.failed_attempts = 0
            st.success("✅ Access restored! Go to Retrieve Data.")
        else:
            st.error("❌ Invalid password.")
