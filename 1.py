import os
import random
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QGridLayout, QPushButton, QLabel, QWidget, QMenuBar, QStatusBar, QAction, QFileDialog, QMessageBox, QInputDialog, QLineEdit)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt

class SecureDataSuite(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window properties
        self.setWindowTitle("SecureData Suite")
        self.setGeometry(100, 100, 500, 600)
        self.setWindowIcon(QIcon("icon.png"))  # Add your custom icon file

        self.central_widget = QWidget()
        self.central_widget.setStyleSheet("background-color: #f0f0f0;")
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout()

        # Setup UI Components
        self.setup_menu()
        self.setup_info_section()
        self.setup_buttons()

        # Set Main Layout
        self.central_widget.setLayout(self.main_layout)

    def setup_info_section(self):
        # Info Section
        info_layout = QVBoxLayout()
        info_layout.setSpacing(0)  # Remove extra space between widgets
        info_layout.setContentsMargins(0, 0, 0, 0)  # Remove margins around the layout

        # Title Label
        title_label = QLabel("Welcome to SecureData Suite")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")

        # Description Label
        description_label = QLabel("Manage your files and data securely and efficiently.")
        description_label.setAlignment(Qt.AlignCenter)
        description_label.setStyleSheet("font-size: 14px;")

        # Add labels to the info layout
        info_layout.addWidget(title_label)
        info_layout.addWidget(description_label)

        # Add the info layout to the main layout
        self.main_layout.addLayout(info_layout)

    def setup_buttons(self):
        # Create a widget for the buttons
        button_widget = QWidget()
        button_layout = QGridLayout()

        # Buttons
        btn1 = QPushButton("File Shredder")
        btn2 = QPushButton("File Encryption")
        btn3 = QPushButton("Automated Backups")
        btn4 = QPushButton("Password Manager")

        btn1.clicked.connect(self.file_shredder)

        for btn in [btn1, btn2, btn3, btn4]:
            btn.setFixedSize(150, 50)
            btn.setStyleSheet("background-color: #d3d3d3; font-size: 14px;")

        # Adding buttons to the grid layout
        button_layout.addWidget(btn1, 0, 0)
        button_layout.addWidget(btn2, 0, 1)
        button_layout.addWidget(btn3, 1, 0)
        button_layout.addWidget(btn4, 1, 1)

        # Set margins for alignment
        button_layout.setContentsMargins(100, 50, 100, 50)

        button_widget.setLayout(button_layout)

        # Add the button widget to the main layout
        self.main_layout.addWidget(button_widget)

    def setup_menu(self):
        """Set up the menu bar and menu items."""
        menu_bar = self.menuBar()

        # File Menu
        file_menu = menu_bar.addMenu("File")
        file_menu.addAction(self.create_action("Open File", self.open_file))
        file_menu.addAction(self.create_action("Save Settings", self.save_settings))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action("Exit", self.close))

        # Tools Menu
        tools_menu = menu_bar.addMenu("Tools")
        tools_menu.addAction(self.create_action("File Shredder", self.file_shredder))
        tools_menu.addAction(self.create_action("Automated Backups", self.automated_backups))
        tools_menu.addAction(self.create_action("File Encryption", self.file_encryption))
        tools_menu.addAction(self.create_action("Password Manager", self.password_manager))

        # Settings Menu
        settings_menu = menu_bar.addMenu("Settings")
        settings_menu.addAction(self.create_action("Encryption Settings", self.encryption_settings))
        settings_menu.addAction(self.create_action("Backup Settings", self.backup_settings))
        settings_menu.addAction(self.create_action("Theme", self.theme_settings))

        # Security Menu
        security_menu = menu_bar.addMenu("Security")
        security_menu.addAction(self.create_action("Set Master Password", self.set_master_password))
        security_menu.addAction(self.create_action("View Logs", self.view_logs))
        security_menu.addAction(self.create_action("Clear Logs", self.clear_logs))

        # Help Menu
        help_menu = menu_bar.addMenu("Help")
        help_menu.addAction(self.create_action("User Guide", self.user_guide))
        help_menu.addAction(self.create_action("About", self.about))

    def create_action(self, name, handler):
        """Helper to create a menu action."""
        action = QAction(name, self)
        action.triggered.connect(handler)
        return action

    # Menu item callbacks (placeholders for now)
    def open_file(self):
        QMessageBox.information(self, "Open File", "Feature not implemented yet!")

    def save_settings(self):
        QMessageBox.information(self, "Save Settings", "Feature not implemented yet!")

    def file_shredder(self):
        """Open File Shredder window."""
        self.file_shredder_window = FileShredderApp(self)
        self.file_shredder_window.show()

    def automated_backups(self):
        QMessageBox.information(self, "Automated Backups", "Schedule file backups.")

    def file_encryption(self):
        QMessageBox.information(self, "File Encryption", "Encrypt or decrypt files.")

    def password_manager(self):
        QMessageBox.information(self, "Password Manager", "Manage passwords securely.")

    def encryption_settings(self):
        QMessageBox.information(self, "Encryption Settings", "Configure encryption options.")

    def backup_settings(self):
        QMessageBox.information(self, "Backup Settings", "Configure backup options.")

    def theme_settings(self):
        QMessageBox.information(self, "Theme Settings", "Switch between themes.")

    def set_master_password(self):
        # Zobrazí dialog pro zadání hesla
        new_password, ok = QInputDialog.getText(self, "Nastavit hlavní heslo", "Zadejte nové hlavní heslo:", QLineEdit.Password)
        
        if ok and new_password:
            # Uložte heslo (může být šifrováno pro větší bezpečnost)
            self.save_master_password(new_password)
            QMessageBox.information(self, "Úspěch", "Hlavní heslo bylo úspěšně nastaveno.")
        else:
            QMessageBox.warning(self, "Chyba", "Nebylo zadáno platné heslo.")

    def save_master_password(self, password):
        """Uložení hesla do souboru"""
        with open("master_password.txt", "w") as file:
            file.write(password)

    def verify_master_password(self):
        """Ověření hlavního hesla"""
        password, ok = QInputDialog.getText(self, "Ověření hesla", "Zadejte hlavní heslo:", QLineEdit.Password)
        
        if ok:
            try:
                with open("master_password.txt", "r") as file:
                    stored_password = file.read()
                if password == stored_password:
                    return True
                else:
                    QMessageBox.warning(self, "Chyba", "Nesprávné hlavní heslo.")
                    return False
            except FileNotFoundError:
                QMessageBox.warning(self, "Chyba", "Hlavní heslo není nastaveno.")
                return False

    def view_logs(self):
        """Display the application activity logs."""
        if self.verify_master_password():
            try:
                with open("app_logs.txt", "r") as log_file:
                    log_content = log_file.read()
                    QMessageBox.information(self, "Activity Logs", log_content)
            except FileNotFoundError:
                QMessageBox.warning(self, "Error", "Log file not found!")

    def clear_logs(self):
        """Clear the activity logs."""
        if self.verify_master_password():
            try:
                with open("app_logs.txt", "w") as log_file:
                    log_file.truncate(0)  # Clear the log file content
                QMessageBox.information(self, "Success", "Activity logs cleared.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to clear logs: {str(e)}")

    def user_guide(self):
        QMessageBox.information(self, "User Guide", "Open the user guide.")

    def about(self):
        QMessageBox.information(self, "About", "SecureData Suite v1.0\nDeveloped by [Your Name].")

    def write_log(self, message):
        """Write a log entry."""
        with open("app_logs.txt", "a") as log_file:
            log_file.write(message + "\n")


class FileShredderApp(QMainWindow):
    def __init__(self, parent):
        super().__init__()
        self.setWindowTitle("File Shredder")
        self.setGeometry(100, 100, 400, 200)
        self.parent = parent  # Reference to the parent (SecureDataSuite)

        # UI Components
        self.label = QLabel("Vyberte soubor k bezpečnému smazání:", self)
        self.label.setStyleSheet("font-size: 14px;")

        self.shred_button = QPushButton("Vybrat a smazat soubor", self)
        self.shred_button.clicked.connect(self.select_and_shred_file)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.shred_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def select_and_shred_file(self):
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(self, "Vyberte soubor", "", "All Files (*.*)")
        if file_path:
            self.label.setText(f"Zpracovávám soubor: {file_path}")
            try:
                self.shred_file(file_path)
                self.label.setText("Soubor byl bezpečně smazán!")
                self.parent.write_log(f"File shredded: {file_path}")  # Log the action
            except Exception as e:
                self.label.setText(f"Chyba: {str(e)}")

    def shred_file(self, file_path):
        """Přepisuje a maže soubor"""
        file_size = os.path.getsize(file_path)

        # Overwrite file with random data a few times
        with open(file_path, 'wb') as file:
            for _ in range(3):  # Overwrite 3 times
                file.write(os.urandom(file_size))

        # Now delete the file
        os.remove(file_path)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureDataSuite()
    window.show()
    sys.exit(app.exec_())
