import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants and Settings ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Helper Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# === Load Existing User Data ===
stored_data = load_data()

# === Sidebar Navigation ===
st.sidebar.title("🔐 Navigation")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Go to", menu)

# === Logout Option ===
if st.session_state.authenticated_user:
    st.sidebar.markdown(f"👤 Logged in as: **{st.session_state.authenticated_user}**")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.authenticated_user = None
        st.success("🔓 You have been logged out.")

# === Pages ===
st.title("🔐 Secure Data Encryption System")

if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("""
    This is a secure data encryption system built with **Streamlit**.  
    It allows users to:
    - Register and log in securely
    - Encrypt sensitive data using a personal passkey
    - Retrieve and decrypt stored data
    - Automatically locks out after multiple failed login attempts
    """)

elif choice == "Register":
    st.subheader("✍️ Register New User")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[username] = {"password": hash_password(password), "data": []}
                save_data(stored_data)
                st.success("✅ Registration successful!")
        else:
            st.error("❌ Both fields are required.")

elif choice == "Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🙋‍♂️ Welcome back, {username}!")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("⛔ Too many failed attempts. Locked for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login to access this section.")
    else:
        st.subheader("📝 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Passkey", type="password")

        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully.")
            else:
                st.error("❌ Both data and passkey are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("📌 Please login to view stored data.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data stored yet.")
        else:
            st.markdown("### Encrypted Entries:")
            for i, item in enumerate(user_data, 1):
                st.code(f"#{i}: {item}", language="text")

            encrypted_input = st.text_area("Enter Encrypted Text to Decrypt")
            passkey = st.text_input("Decryption Passkey", type="password")

            if st.button("Decrypt"):
                if encrypted_input and passkey:
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decryption successful!")
                        st.markdown(f"**Decrypted Message:**\n```\n{result}\n```")
                    else:
                        st.error("❌ Incorrect passkey or corrupted encrypted text.")
                else:
                    st.warning("Please enter both the encrypted text and passkey.")

# === Footer ===
st.markdown("""
---
📦 **Secure Data Encryption System** | Developed by [Mehwish Naz]  
🔐 Built with Python & Streamlit  
💡 Source code available on [GitHub](https://github.com/Mehwishnaz1603cls
            )
""", unsafe_allow_html=True)
