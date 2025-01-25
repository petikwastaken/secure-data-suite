import os
import sys
import ctypes
import base64
import json
import hashlib
import cv2
import numpy as np
import pygame
import platform
from PyPDF2 import PdfReader
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PyQt5.QtWidgets import (QApplication, QMainWindow,QFileDialog, QVBoxLayout, QGridLayout, QPushButton, QLabel, QWidget, QAction, QFileDialog, QMessageBox, QInputDialog, QLineEdit)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtWidgets import QFileDialog
from PIL import Image, ImageSequence

# Nastavení AppUserModelID pro Windows
if platform.system() == "Windows":
    myappid = 'SecureDataSuite.1.0'  # Unikátní ID pro aplikaci
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)


def play_intro_animation():
    """Plays the intro video (MP4) and sound using pygame, with a circular window."""
    pygame.init()

    # Set up the screen size
    screen_width, screen_height = 300, 200
    screen = pygame.display.set_mode((screen_width, screen_height), pygame.NOFRAME)  # No borders or decorations
    pygame.display.set_caption("Secure Data Suite")

    # Load MP4 video and sound
    video_path = "startup.mp4"  # Replace with your video path
    cap = cv2.VideoCapture(video_path)

    if not cap.isOpened():
        print("Error: Could not open video file.")
        return

    # Get video properties
    fps = 60 
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    frame_duration = 1 / fps  # Duration of each frame in seconds

    # Load sound
    sound = pygame.mixer.Sound("startup.wav")  # Replace with your sound path

    # Start animation and delay audio start if needed
    clock = pygame.time.Clock()
    running = True
    frame_index = 0
    start_time = pygame.time.get_ticks()

    # Delayed audio start time (in milliseconds)
    delay = 50  # Delay sound by 0.05 seconds
    audio_started = False

    # Create a circular mask for the window
    circle_surface = pygame.Surface((screen_width, screen_height), pygame.SRCALPHA)  # Transparent surface
    pygame.draw.circle(circle_surface, (255, 255, 255), (screen_width // 2, screen_height // 2), screen_width // 2)  # Draw circle mask

    while running:
        ret, frame = cap.read()
        if not ret:  # End of video
            break

        # Resize frame to fit the screen (screen width and height should not be swapped)
        frame = cv2.resize(frame, (screen_width, screen_height))

        # Rotate the frame by 90 degrees counterclockwise
        frame = cv2.transpose(frame)  # Transpose the frame
        frame = cv2.flip(frame, flipCode=0)  # Flip vertically to get the correct 90-degree counterclockwise rotation

        # Play sound after delay
        if not audio_started and pygame.time.get_ticks() - start_time >= delay:
            sound.play()  # Start the sound after the delay
            audio_started = True

        # Convert the frame to a format Pygame can handle
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)  # Convert BGR to RGB for pygame
        frame_surface = pygame.surfarray.make_surface(frame)

        # Create a copy of the screen and fill it with the circle surface
        screen.fill((0, 0, 0))  # Fill the screen with black
        screen.blit(circle_surface, (0, 0), special_flags=pygame.BLEND_RGBA_MIN)  # Apply circle mask

        # Blit the video frame into the circular area
        screen.blit(frame_surface, (0, 0))

        pygame.display.flip()

        clock.tick(fps)

    # Clean up
    cap.release()
    pygame.quit()
    cv2.destroyAllWindows()

##########################
#       MAIN WINDOW      #
##########################

class SecureDataSuite(QMainWindow):
    def __init__(self):
        super().__init__()

        # Vlastnosti okna
        self.setWindowTitle("SecureData Suite")
        self.setGeometry(700, 400, 200, 450)
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

        label = QLabel(self)
        pixmap = QPixmap("banner.png")  # Načtení obrázku
        pixmap = pixmap.scaled(520, 220)
        label.setPixmap(pixmap)  # Nastavení obrázku na QLabel
        label.resize(pixmap.width(), pixmap.height())
        label.move(5, 20)  # Nastavení pozice QLabel v okně

        # Mrdka at se buttons nerozjedou do pice
        description_label = QLabel("             ")
        description_label.setAlignment(Qt.AlignCenter)
        description_label.setStyleSheet("font-size: 14px;")

        info_layout.addWidget(description_label)
        self.main_layout.addLayout(info_layout)

        # Creating log entry when the app starts
        self.create_startup_log()
    
    def create_startup_log(self):
        try:
            with open("app_logs.txt", "a") as file:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                file.write(f"App started at {timestamp}\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")

    def setup_buttons(self):
        # Sekce s tlačítky
        button_widget = QWidget()
        button_layout = QGridLayout()

        btn1 = QPushButton("File Shredder")
        btn2 = QPushButton("File Encryption")
        btn3 = QPushButton("Data Scrubber")
        btn4 = QPushButton("Password Manager")

        btn1.clicked.connect(self.file_shredder)
        btn2.clicked.connect(self.file_encryption)
        btn3.clicked.connect(self.scrub_metadata)
        btn4.clicked.connect(self.password_manager)


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
        tools_menu.addAction(self.create_action("Data Scrubber", self.scrub_metadata))
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

    def scrub_metadata(self):
        self.file_shredder_window = FileMetadataScrubberApp(self)
        self.file_shredder_window.show()
        
    def file_encryption(self):
        self.file_encrypter_window = FileEncrypterApp(self)
        self.file_encrypter_window.show()

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
        QMessageBox.information(self, "User Guide",
                                "Welcome to the File Management Application!\n\n"
                                "1. File Shredding: Securely deletes files by rewriting them 3 times and then permanently deleting them.\n"
                                "2. File Encryption & Decryption: Encrypt and decrypt files using AES-256 encryption for maximum security.\n"
                                "3. Metadata Scrubber: Removes sensitive metadata from files to ensure privacy.\n"
                                "4. Password Manager: Manage your passwords securely (under development).\n\n"
                                "Additional Features:\n"
                                "- In the Settings menu, you can switch themes between Dark and White modes.\n\n"
                                "Your personal safety is our priority 🔝")

    def about(self):
        QMessageBox.information(self, "About", "SecureData Suite version 1.0\n"
                                               "Developed by 1K")
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
        # Open file dialog for multiple file selection
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select files", "", "All Files (*.*)")
        if file_paths:
            self.label.setText(f"Processing {len(file_paths)} file(s)...")
            failed_files = []
            for file_path in file_paths:
                try:
                    self.shred_file(file_path)
                except Exception as e:
                    failed_files.append((file_path, str(e)))

            # Display result
            if failed_files:
                error_message = "\n".join([f"{file}: {error}" for file, error in failed_files])
                self.label.setText(f"Errors occurred:\n{error_message}")
            else:
                self.label.setText("All files securely deleted! 🤯")
                self.label.setStyleSheet("font-size: 25px; font-weight: bold;")


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

def scrub_image_metadata(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    
    # Handling different file types
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
        from PIL import Image

        # Load image
        with Image.open(file_path) as img:
            scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed{os.path.splitext(file_path)[1]}"
            img.save(scrubbed_file_path, format=img.format)

    elif file_path.lower().endswith('.pdf', '.txt'):
        # Scrubbing metadata for PDF files
        reader = PdfReader(file_path)
        scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed.pdf"
        with open(scrubbed_file_path, 'wb') as f_out:
            for page in reader.pages:
                f_out.write(page.extract_text().encode('utf-8'))

    else:
        raise ValueError("Unsupported file type for metadata scrubbing.")

    return scrubbed_file_path

class FileMetadataScrubberApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Metadata Scrubber")
        self.setGeometry(770, 600, 400, 200)

        self.label = QLabel("Select files to scrub metadata:", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 14px;")

        self.scrub_button = QPushButton("Select and scrub metadata", self)
        self.scrub_button.clicked.connect(self.select_and_scrub_metadata)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.scrub_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def select_and_scrub_metadata(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select files", "", "All Files (*.*)")
        if file_paths:
            for file_path in file_paths:
                try:
                    scrubbed_file_path = scrub_image_metadata(file_path)
                    self.label.setText(f"Metadata scrubbed succesfuly!🧽")
                    self.label.setStyleSheet("font-size: 25px; font-weight: bold;")
                except Exception as e:
                    self.label.setText(f"Error: {str(e)}")
                try:
                    with open("app_logs.txt", "a") as file:
                        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                        file.write(f"Metadata securely scrubbed: {file_path} at {timestamp}\n")
                except Exception as e: 
                    print(e)

##########################
# FILE ENCRYPTION MODULE #
##########################

# File to store the password
PASSWORD_FILE = "master_password.txt"

def get_key_from_password(password: str) -> bytes:
    """Generate a 256-bit AES key from the provided password."""
    return hashlib.sha256(password.encode()).digest()


def encrypt_file(file_path, key):
    """Encrypt a file using AES encryption."""
    with open(file_path, "rb") as f:
        plaintext = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(cipher.iv + ciphertext)

    return encrypted_path


def decrypt_file(file_path, key):
    """Decrypt a file using AES decryption."""
    with open(file_path, "rb") as f:
        data = f.read()

    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    decrypted_path = file_path.replace(".enc", "")
    with open(decrypted_path, "wb") as f:
        f.write(plaintext)

    return decrypted_path


def save_password(password: str):
    """Save the password to a file."""
    with open(PASSWORD_FILE, "w") as f:
        f.write(password)


def load_passwords():
    # Pokud třeba načítáš master password ze souboru nebo jiné logiky
    return "master_password"  # Změň podle potřeby

    try:
        with open(self.passwords_file, "rb") as f:
            encrypted_data = f.read()

        if encrypted_data:  # Pokud soubor není prázdný
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            self.passwords = json.loads(decrypted_data.decode("utf-8"))
        else:
            self.passwords = {}

    except Exception as e:
        QMessageBox.critical(self, "Error", f"Failed to load passwords: {e}")
        self.passwords = {}



def is_password_set() -> bool:
    """Check if the password file exists."""
    return os.path.exists(PASSWORD_FILE)


class FileEncrypterApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Encryption")
        self.setGeometry(770, 600, 400, 300)

        # UI Components
        self.label = QLabel("Select a file to encrypt or decrypt:", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 14px;")

        self.encrypt_button = QPushButton("Encrypt File", self)
        self.decrypt_button = QPushButton("Decrypt File", self)
        self.encrypt_button.clicked.connect(self.encrypt_file_action)
        self.decrypt_button.clicked.connect(self.decrypt_file_action)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def set_password_action(self):
        if is_password_set():
            QMessageBox.warning(self, "Warning", "Password is already set!")
            return

        password, ok = QInputDialog.getText(
            self, "Set Password", "Enter a new password:", QLineEdit.Password
        )
        if ok and password:
            save_password(password)
            QMessageBox.information(self, "Success", "Password has been set successfully!")

    def verify_password(self):
        if not is_password_set():
            QMessageBox.warning(self, "Error", "No password is set. Please set a password first.")
            return None

        password, ok = QInputDialog.getText(
            self, "Verify Password", "Enter your password:", QLineEdit.Password
        )
        if ok and password:
            saved_password = load_passwords()
            if password == saved_password:
                return True
            else:
                QMessageBox.critical(self, "Error", "Incorrect password!")
                return False
        return None

    def encrypt_file_action(self):
        if not self.verify_password():
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            password = load_passwords()
            key = get_key_from_password(load_passwords())

            try:
                encrypted_path = encrypt_file(file_path, key)
                QMessageBox.information(
                    self, "Success", f"File encrypted successfully! Saved at: {encrypted_path}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")

    def decrypt_file_action(self):
        if not self.verify_password():
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            password = load_passwords()
            key = get_key_from_password(password)
            try:
                decrypted_path = decrypt_file(file_path, key)
                QMessageBox.information(
                    self, "Success", f"File decrypted successfully! Saved at: {decrypted_path}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView

class PasswordManagerApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Manager")
        self.setGeometry(770, 600, 500, 400)

        # UI Components
        self.label = QLabel("Password Manager", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 18px; font-weight: bold;")

        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Website/App", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.add_button = QPushButton("Add Password", self)
        self.add_button.clicked.connect(self.add_password)

        self.load_button = QPushButton("Load Passwords", self)
        self.load_button.clicked.connect(self.load_passwords)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.table)
        layout.addWidget(self.add_button)
        layout.addWidget(self.load_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def add_password(self):
        if not self.parent().verify_master_password():
            return

        website, ok1 = QInputDialog.getText(self, "Add Password", "Enter Website/App:")
        if not ok1 or not website:
            return

        password, ok2 = QInputDialog.getText(self, "Add Password", "Enter Password:", QLineEdit.Password)
        if not ok2 or not password:
            return

        try:
            with open("passwords.enc", "ab") as f:
                key = get_key_from_password(load_passwords())
                cipher = AES.new(key, AES.MODE_CBC)
                data = f"{website}|{password}".encode()
                ciphertext = cipher.encrypt(pad(data, AES.block_size))
                f.write(cipher.iv + ciphertext)

            QMessageBox.information(self, "Success", "Password added successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add password: {str(e)}")

    def load_passwords(self):
        if not self.parent().verify_master_password():
            return

        try:
            with open("passwords.enc", "rb") as f:
                key = get_key_from_password(load_passwords())
                self.table.setRowCount(0)

                while True:
                    iv = f.read(AES.block_size)
                    if not iv:
                        break

                    ciphertext = f.read(64)  # Read each encrypted block
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
                    website, password = data.split("|")

                    row_position = self.table.rowCount()
                    self.table.insertRow(row_position)
                    self.table.setItem(row_position, 0, QTableWidgetItem(website))
                    self.table.setItem(row_position, 1, QTableWidgetItem(password))

            QMessageBox.information(self, "Success", "Passwords loaded successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load passwords: {str(e)}")

# Update SecureDataSuite to integrate PasswordManagerApp
def password_manager(self):
    self.password_manager_window = PasswordManagerApp(self)
    self.password_manager_window.show()

SecureDataSuite.password_manager = password_manager

# RUN #
if __name__ == "__main__":
    # Play intro animation
    play_intro_animation()

    app = QApplication(sys.argv)
    window = SecureDataSuite()
    window.show()
    sys.exit(app.exec())