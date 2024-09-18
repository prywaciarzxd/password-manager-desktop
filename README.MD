# Password Manager

## Description

This project is a password manager written in Python. It allows you to add, view, delete, and copy passwords to the clipboard. Additionally, it includes a script for adding an entry to the Windows context menu, enabling quick access to the password manager.

## Requirements

- Python 3.x
- Required packages are specified in the `requirements.txt` file

## Installation

1. **Clone or download the repository:**

    ```bash
    git clone https://github.com/prywciarzxd/password-manager-desktop.git
    cd password-manager-desktop
    ```

2. **Install the required packages:**

    Ensure all required packages are installed:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running the Password Manager

1. **Run `passwordmanager.py`:**

    To start the password manager, use the following command:

    ```bash
    python passwordmanager.py
    ```

2. **Interface:**

    - **1. Add password** - Add a new password entry to the database.
    - **2. View passwords** - Display all saved passwords.
    - **3. Delete password** - Remove a password entry based on `service` and `email`.
    - **4. Copy password to clipboard** - Copy a password to the clipboard based on `service` and `email`.
    - **5. Delete database** - Delete the entire password database.
    - **6. Exit** - Encrypt the database and exit the program.

### Adding a Context Menu Entry

1. **Run `main.py` as an administrator:**

    To add the context menu entry, run `main.py` with administrative privileges:

    ```bash
    python main.py
    ```

    This script adds an "Open Password Manager" option to the Windows context menu, allowing quick access to the password manager.

## Required Packages

The `requirements.txt` file contains a list of required packages:

## Notes

- **Security:** The database is encrypted using a Fernet key. Ensure you use a strong passphrase and securely store the encryption key.

- **Administrator Privileges:** Adding a context menu entry requires administrative privileges. Ensure you run `main.py` with the appropriate permissions.

## License

This project is licensed under the [MIT License](LICENSE).

