import re
import os
import sqlite3
import getpass
import base64
import ctypes
import sys
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Function to check if the script is running with administrator privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Relaunch the script with admin privileges if not already running as admin
def run_as_admin():
    if not is_admin():
        print("Requesting admin privileges...")
        # Re-launch the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

# Generate a Fernet key from a user's passphrase
def create_key(passphrase):
    # Derive a key from the passphrase using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use the SHA256 object, not a string
        length=32,
        salt=b'salt',  # Ideally, this should be a securely generated random value and stored
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))  # Generate the encryption key
    
    # Return a Fernet object initialized with the key
    return Fernet(key)

# Encrypt the entire database file
def encrypt_db(filename, fernet):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            data = f.read()
        encrypted_data = fernet.encrypt(data)  # Now, 'fernet' is a Fernet instance, not bytes
        with open(filename, 'wb') as f:
            f.write(encrypted_data)

# Decrypt the entire database file
def decrypt_db(filename, fernet):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
        try:
            data = fernet.decrypt(encrypted_data)
            with open(filename, 'wb') as f:
                f.write(data)
        except Exception as e:
            print("Invalid passphrase or corrupted database.")
            exit()

# Validate the email format using a simple regex
def validate_email(email):
    # Simple regex for basic email validation
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if re.match(email_regex, email):
        return True
    else:
        print("Invalid email format.")
        return False

# Initialize the SQLite database (create the table if it doesn't exist)
def init_db():
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            email TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Add a password entry to the database
def add_password(service, username, email, password):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    # Use parameterized queries to prevent SQL injection
    c.execute('INSERT INTO passwords (service, username, email, password) VALUES (?, ?, ?, ?)', 
              (service, username, email, password))
    conn.commit()
    conn.close()

# Retrieve all passwords from the database
def get_passwords():
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('SELECT service, username, email, password FROM passwords')
    rows = c.fetchall()
    conn.close()
    return rows

# Delete a password entry by service and email
def delete_password(service, email):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('DELETE FROM passwords WHERE service = ? AND email = ?', (service, email))
    conn.commit()
    conn.close()

# Delete the entire database
def delete_db():
    if os.path.exists('password_manager.db'):
        os.remove('password_manager.db')
        print("Database deleted.")
    else:
        print("Database not found.")

# Copy a password to the clipboard based on service:email
def copy_password_to_clipboard(service, email):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('SELECT password FROM passwords WHERE service = ? AND email = ?', (service, email))
    result = c.fetchone()
    conn.close()

    if result:
        password = result[0]
        pyperclip.copy(password)
        print("Password copied to clipboard.")
    else:
        print("No matching entry found.")

def main():
    db_filename = 'password_manager.db'

    # Get the passphrase from the user
    passphrase = getpass.getpass("Enter your passphrase: ")
    fernet = create_key(passphrase)

    # Decrypt the database before using it
    decrypt_db(db_filename, fernet)
    init_db()

    while True:
        choice = input("1. Add password\n2. View passwords\n3. Delete password\n4. Copy password to clipboard\n5. Delete database\n6. Exit\nChoose an option: ")
        
        if choice == '1':
            service = input("Enter service name: ")
            email = input("Enter email: ")

            if not validate_email(email):
                print("Invalid email. Please try again.")
                continue  # Go back to the menu

            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            add_password(service, username, email, password)
            print("Password added.")
        
        elif choice == '2':
            passwords = get_passwords()
            for service, username, email, password in passwords:
                print(f"Service: {service}, Email: {email}, Username: {username}, Password: {password}")
        
        elif choice == '3':
            entry = input("Enter service and email in the format service:email: ")
            try:
                service, email = entry.split(':')
                if validate_email(email):
                    delete_password(service, email)
                    print("Password entry deleted.")
                else:
                    print("Invalid email. Please try again.")
            except ValueError:
                print("Invalid format. Use service:email.")
        
        elif choice == '4':
            entry = input("Enter service and email in the format service:email: ")
            try:
                service, email = entry.split(':')
                if validate_email(email):
                    copy_password_to_clipboard(service, email)
                else:
                    print("Invalid email format.")
            except ValueError:
                print("Invalid format. Use service:email.")

        elif choice == '5':
            delete_db()

        elif choice == '6':
            # Encrypt the database before exiting
            encrypt_db(db_filename, fernet)
            print("Database encrypted. Exiting.")
            break

if __name__ == "__main__":
    run_as_admin()  # Ensure the script is run with admin privileges
    main()
