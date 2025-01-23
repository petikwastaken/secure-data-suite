import sys
import os
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
                             QLineEdit, QLabel, QMessageBox, QListWidget, QInputDialog)
from cryptography.fernet import Fernet

# Constants for encryption
KEY_FILE = "key.key"
DATA_FILE = "data.enc"
MASTER_PASSWORD_FILE = "master_password.enc"

def generate_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Loads the encryption key from a file."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        return key_file.read()

def encrypt_data(data):
    """Encrypts the given data using the encryption key."""
    key = load_key()
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(data):
    """Decrypts the given data using the encryption key."""
    key = load_key()
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

def load_passwords():
    """Loads the stored passwords from the encrypted file."""
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as file:
        encrypted_data = file.read()
        if not encrypted_data:
            return {}
        decrypted_data = decrypt_data(encrypted_data)
        return json.loads(decrypted_data)

def save_passwords(passwords):
    """Saves the passwords to the encrypted file."""
    data = json.dumps(passwords)
    encrypted_data = encrypt_data(data)
    with open(DATA_FILE, 'wb') as file:
        file.write(encrypted_data)

def set_master_password(master_password):
    """Sets and encrypts the master password."""
    encrypted_master_password = encrypt_data(master_password)
    with open(MASTER_PASSWORD_FILE, 'wb') as file:
        file.write(encrypted_master_password)

def verify_master_password(master_password):
    """Verifies the master password by decrypting and comparing."""
    if not os.path.exists(MASTER_PASSWORD_FILE):
        return False
    with open(MASTER_PASSWORD_FILE, 'rb') as file:
        encrypted_master_password = file.read()
        decrypted_master_password = decrypt_data(encrypted_master_password)
        return master_password == decrypted_master_password

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.passwords = load_passwords()
        self.init_ui()

    def init_ui(self):
        if not os.path.exists(MASTER_PASSWORD_FILE):
            self.setup_master_password()
        else:
            self.prompt_master_password()

    def setup_master_password(self):
        """Prompts the user to set up a master password."""
        while True:
            password, ok = QInputDialog.getText(self, "Set Master Password", "Create a master password:", QLineEdit.Password)
            if ok and password:
                confirm_password, ok = QInputDialog.getText(self, "Set Master Password", "Confirm master password:", QLineEdit.Password)
                if ok and password == confirm_password:
                    set_master_password(password)
                    QMessageBox.information(self, "Success", "Master password set successfully.")
                    self.main_ui()
                    break
                else:
                    QMessageBox.warning(self, "Error", "Passwords do not match. Try again.")
            elif not ok:
                sys.exit()

    def prompt_master_password(self):
        """Prompts the user to enter the master password."""
        attempts = 3
        while attempts > 0:
            password, ok = QInputDialog.getText(self, "Enter Master Password", "Enter your master password:", QLineEdit.Password)
            if ok and verify_master_password(password):
                QMessageBox.information(self, "Success", "Access granted.")
                self.main_ui()
                return
            else:
                attempts -= 1
                QMessageBox.warning(self, "Error", f"Incorrect password. {attempts} attempts remaining.")
        QMessageBox.critical(self, "Error", "Access denied. Exiting application.")
        sys.exit()

    def main_ui(self):
        """Sets up the main UI for the password manager."""
        main_layout = QVBoxLayout()

        self.list_widget = QListWidget()
        self.list_widget.addItems(self.passwords.keys())
        main_layout.addWidget(self.list_widget)

        button_layout = QHBoxLayout()
        add_button = QPushButton("Add")
        add_button.clicked.connect(self.add_password)
        button_layout.addWidget(add_button)

        view_button = QPushButton("View")
        view_button.clicked.connect(self.view_password)
        button_layout.addWidget(view_button)

        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self.delete_password)
        button_layout.addWidget(delete_button)

        main_layout.addLayout(button_layout)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def add_password(self):
        name, ok = QInputDialog.getText(self, "Add Password", "Enter account name:")
        if ok and name:
            password, ok = QInputDialog.getText(self, "Add Password", "Enter password:", QLineEdit.Password)
            if ok and password:
                self.passwords[name] = password
                save_passwords(self.passwords)
                self.list_widget.addItem(name)

    def view_password(self):
        selected_item = self.list_widget.currentItem()
        if selected_item:
            name = selected_item.text()
            password = self.passwords.get(name, "")
            QMessageBox.information(self, "View Password", f"Account: {name}\nPassword: {password}")
        else:
            QMessageBox.warning(self, "View Password", "No account selected.")

    def delete_password(self):
        selected_item = self.list_widget.currentItem()
        if selected_item:
            name = selected_item.text()
            confirm = QMessageBox.question(self, "Delete Password", f"Are you sure you want to delete the password for {name}?", QMessageBox.Yes | QMessageBox.No)
            if confirm == QMessageBox.Yes:
                del self.passwords[name]
                save_passwords(self.passwords)
                self.list_widget.takeItem(self.list_widget.row(selected_item))
        else:
            QMessageBox.warning(self, "Delete Password", "No account selected.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    manager = PasswordManager()
    manager.resize(400, 300)
    manager.show()
    sys.exit(app.exec_())
