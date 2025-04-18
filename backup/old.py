from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QMessageBox, QFileDialog
)
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtCore import Qt
import json
import sys
from file_shredder import FileShredderApp

class SecureDataSuite(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window properties
        self.setWindowTitle("SecureData Suite")
        self.setFixedSize(550, 600)
        self.setWindowIcon(QIcon("icon.png"))  # Add your custom icon file

        # Set up the main layout
        main_widget = QWidget(self)
        self.setCentralWidget(main_widget)

        layout = QVBoxLayout()
        main_widget.setLayout(layout)

        # Set up the menu bar
        self.setup_menu()

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
        """Open a file using QFileDialog."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if file_path:
            # Read file content
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    # Display the content in a message box
                    QMessageBox.information(self, "File Content", content)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open file: {e}")
        else:
            QMessageBox.warning(self, "Open File", "No file selected.")

    def save_settings(self):
        """Save settings to a file."""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Settings", "", "JSON Files (*.json);;All Files (*)")
        if file_path:
            try:
                # Data for saving
                settings_data = {
                    "theme": "dark",
                    "backup_frequency": "daily",
                    "encryption_enabled": True
                }
                # Write data to the file
                with open(file_path, "w") as file:
                    json.dump(settings_data, file, indent=4)
                QMessageBox.information(self, "Success", f"Settings saved successfully at:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")
        else:
            QMessageBox.warning(self, "Cancelled", "Save operation cancelled.")

    def file_shredder(self):
        # Otevře okno File Shredderu
        self.file_shredder_window = FileShredderApp()
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
        QMessageBox.information(self, "Set Master Password", "Set or update the master password.")

    def view_logs(self):
        QMessageBox.information(self, "View Logs", "View application activity logs.")

    def clear_logs(self):
        QMessageBox.information(self, "Clear Logs", "Clear all activity logs.")

    def user_guide(self):
        QMessageBox.information(self, "User Guide", "Open the user guide.")

    def about(self):
        QMessageBox.information(self, "About", "SecureData Suite v1.0\nDeveloped by [Your Name].")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureDataSuite()
    window.show()
    sys.exit(app.exec())
