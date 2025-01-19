import os
import sys
import ctypes
import platform
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QGridLayout, QPushButton, QLabel, QWidget, QMenuBar, QStatusBar, QAction, QFileDialog, QMessageBox, QInputDialog, QLineEdit)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QDateTime

# Nastavení AppUserModelID pro Windows
if platform.system() == "Windows":
    myappid = 'SecureDataSuite.1.0'  # Unikátní ID pro aplikaci
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
##########################
#       MAIN WINDOW      #
##########################
class SecureDataSuite(QMainWindow):
    def __init__(self):
        super().__init__()

        # Vlastnosti okna
        self.setWindowTitle("SecureData Suite")
        self.setGeometry(700, 400, 200, 400)
        self.setWindowIcon(QIcon("icon.ico"))  # Ikona aplikace (musí být ve formátu .ico)

        self.central_widget = QWidget()
        self.central_widget.setStyleSheet("background-color: #f0f0f0;")
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout()

        # Vytvoření uživatelského rozhraní
        self.setup_menu()
        self.setup_info_section()
        self.setup_buttons()

        # Nastavení hlavního layoutu
        self.central_widget.setLayout(self.main_layout)

        # Výchozí téma (světlý režim)
        self.is_dark_mode = False
        self.apply_theme()

    def setup_info_section(self):
        # Sekce s informacemi
        info_layout = QVBoxLayout()
        info_layout.setSpacing(0)
        info_layout.setContentsMargins(0, 0, 0, 0)

        # Nadpis
        title_label = QLabel("Welcome to SecureData Suite")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")

        # Popis
        description_label = QLabel("Manage your files and data securely and efficiently.")
        description_label.setAlignment(Qt.AlignCenter)
        description_label.setStyleSheet("font-size: 14px;")

        info_layout.addWidget(title_label)
        info_layout.addWidget(description_label)
        self.main_layout.addLayout(info_layout)

    def setup_buttons(self):
        # Sekce s tlačítky
        button_widget = QWidget()
        button_layout = QGridLayout()

        btn1 = QPushButton("File Shredder")
        btn2 = QPushButton("File Encryption")
        btn3 = QPushButton("Automated Backups")
        btn4 = QPushButton("Password Manager")

        btn1.clicked.connect(self.file_shredder)

        for btn in [btn1, btn2, btn3, btn4]:
            btn.setFixedSize(150, 50)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #444;
                    color: #fff;
                    font-size: 14px;
                    font-weight: bold;
                    border: 2px solid #555;
                    border-radius: 8px;
                }
                QPushButton:hover {
                    background-color: #555;
                }
                QPushButton:pressed {
                    background-color: #666;
                }
            """)

        button_layout.addWidget(btn1, 0, 0)
        button_layout.addWidget(btn2, 0, 1)
        button_layout.addWidget(btn3, 1, 0)
        button_layout.addWidget(btn4, 1, 1)
        button_layout.setContentsMargins(100, 50, 100, 50)

        button_widget.setLayout(button_layout)
        self.main_layout.addWidget(button_widget)
##########################
#       MENU BAR         #
##########################
    def setup_menu(self):
        menu_bar = self.menuBar()

        # Menu File
        file_menu = menu_bar.addMenu("File")
        file_menu.addAction(self.create_action("Open File", self.open_file))
        file_menu.addAction(self.create_action("Save Settings", self.save_settings))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action("Exit", self.close))

        # Menu Tools
        tools_menu = menu_bar.addMenu("Tools")
        tools_menu.addAction(self.create_action("File Shredder", self.file_shredder))
        tools_menu.addAction(self.create_action("Automated Backups", self.automated_backups))
        tools_menu.addAction(self.create_action("File Encryption", self.file_encryption))
        tools_menu.addAction(self.create_action("Password Manager", self.password_manager))

        # Menu Settings
        settings_menu = menu_bar.addMenu("Settings")
        settings_menu.addAction(self.create_action("Encryption Settings", self.encryption_settings))
        settings_menu.addAction(self.create_action("Backup Settings", self.backup_settings))
        settings_menu.addAction(self.create_action("Theme", self.toggle_theme))

        # Menu Security
        security_menu = menu_bar.addMenu("Security")
        security_menu.addAction(self.create_action("Set Master Password", self.set_master_password))
        security_menu.addAction(self.create_action("View Logs", self.view_logs))
        security_menu.addAction(self.create_action("Clear Logs", self.clear_logs))

        # Menu Help
        help_menu = menu_bar.addMenu("Help")
        help_menu.addAction(self.create_action("User Guide", self.user_guide))
        help_menu.addAction(self.create_action("About", self.about))

    def create_action(self, name, handler):
        action = QAction(name, self)
        action.triggered.connect(handler)
        return action

    def open_file(self):
        QMessageBox.information(self, "Open File", "Feature not implemented yet!")

    def save_settings(self):
        QMessageBox.information(self, "Save Settings", "Feature not implemented yet!")

    def file_shredder(self):
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
    # DARKMODE / LIGHTMODE #
    def toggle_theme(self):
        # Toggle between dark mode and light mode
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_mode:
            dark_mode_stylesheet = """
            QMainWindow {
                background-color: #2b2b2b;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QPushButton {
                background-color: #444;
                color: #ffffff;
                border: 1px solid #555;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #555;
            }
            QPushButton:pressed {
                background-color: #666;
            }
            QPushButton:disabled {
                background-color: #444;
                color: #888;
            }
            QLabel {
                color: #f0f0f0;
            }
            QMenuBar {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QMenuBar::item {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QMenuBar::item:selected {
                background-color: #444;
            }
            QMenu {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QMenu::item {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QMenu::item:selected {
                background-color: #444;
            }
            """
            self.setStyleSheet(dark_mode_stylesheet)
            self.central_widget.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        else:
            light_mode_stylesheet = """
            QMainWindow {
                background-color: #f0f0f0;
            }
            QWidget {
                background-color: #f0f0f0;
                color: #000000;
            }
            QPushButton {
                background-color: #444;
                color: #ffffff;
                border: 1px solid #555;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #555;
            }
            QPushButton:pressed {
                background-color: #666;
            }
            QPushButton:disabled {
                background-color: #444;
                color: #888;
            }
            QLabel {
                color: #000000;
            }
            QMenuBar {
                background-color: #f0f0f0;
                color: #000000;
            }
            QMenuBar::item {
                background-color: #f0f0f0;
                color: #000000;
            }
            QMenuBar::item:selected {
                background-color: #444;
            }
            QMenu {
                background-color: #f0f0f0;
                color: #000000;
            }
            QMenu::item {
                background-color: #f0f0f0;
                color: #000000;
            }
            QMenu::item:selected {
                background-color: #444;
            }
            """
            self.setStyleSheet(light_mode_stylesheet)
            self.central_widget.setStyleSheet("background-color: #f0f0f0; color: #000000;")
##########################
#    PASSWORD MANAGER    #
##########################
    def set_master_password(self):
        new_password, ok = QInputDialog.getText(self, "Set main password", "Set new main password:", QLineEdit.Password)
        if ok and new_password:
            self.save_master_password(new_password)
            QMessageBox.information(self, "Success", "New password was successfully set.")
        else:
            QMessageBox.warning(self, "Error", "No password entered!")

    def save_master_password(self, password):
        with open("master_password.txt", "w") as file:
            file.write(password)

    def verify_master_password(self):
        password, ok = QInputDialog.getText(self, "Password verification", "Enter the master password:", QLineEdit.Password)
        if ok:
            try:
                with open("master_password.txt", "r") as file:
                    stored_password = file.read()
                if password == stored_password:
                    return True
                else:
                    QMessageBox.warning(self, "Error", "Wrong master password.")
                    return False
            except FileNotFoundError:
                QMessageBox.warning(self, "Error", "Master password is not set.")
                return False

    def view_logs(self):
        if self.verify_master_password():
            if not os.path.exists("app_logs.txt"):
                QMessageBox.warning(self, "No Logs", "No logs found.")
                return
        
            try:
            # Open the log file in the default text editor
                if sys.platform == "win32":
                    os.startfile("app_logs.txt")  # For Windows
                elif sys.platform == "darwin":
                    os.startfile("app_logs.txt")  # For mac
                else:
                    os.system(f"xdg-open app_logs.txt")  # For Linux
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Cannot open logs: {str(e)}")
        
    def clear_logs(self):
        if self.verify_master_password():
            try:
                open("app_logs.txt", "w").close()  # Clear the log file
                QMessageBox.information(self, "Logs Cleared", "Activity logs cleared successfully.")
            except FileNotFoundError:
                QMessageBox.warning(self, "Error", "No logs to clear.")

    def user_guide(self):
        QMessageBox.information(self, "User Guide", "This application helps you manage your files securely.")

    def about(self):
        QMessageBox.information(self, "About", "SecureData Suite version 1.0\nDeveloped by 1K")
##########################
#     FILE SHREDDER      #
##########################
class FileShredderApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Shredder")
        self.setGeometry(770, 600, 400, 200)

        # UI Components
        self.label = QLabel("Select file to securely delete:", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 14px;")

        self.shred_button = QPushButton("Select and delete file", self)
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
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file", "", "All Files (*.*)")
        if file_path:
            self.label.setText(f"Proccesing file: {file_path}")
            try:
                self.shred_file(file_path)
                self.label.setText("File securely terminated🤯!")
                self.label.setStyleSheet("font-size: 25px; font-weight: bold;")
            except Exception as e:
                self.label.setText(f"Error: {str(e)}")

    def shred_file(self, file_path):
        """Přepisuje a maže soubor"""
        file_size = os.path.getsize(file_path)

        with open(file_path, 'wb') as file:
            for _ in range(3):  # Overwrite the file 3 times with random shit
                file.write(os.urandom(file_size))
                file.flush()
                os.fsync(file.fileno())

        os.remove(file_path)  # Delete file
        try:
    # Otevření souboru v režimu přidávání
            with open("app_logs.txt", "a") as file:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                file.write(f"Securely deleted: {file_path} at {timestamp}\n")
        except Exception as e : print(e)

# RUN #
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureDataSuite()
    window.show()
    sys.exit(app.exec())