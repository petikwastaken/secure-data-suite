import time
start = time.time() 
import os
import sys
import ctypes
import base64
import hashlib
import cv2
import numpy as np
import pygame
import platform
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PyQt5.QtWidgets import (QApplication, QMainWindow,QFileDialog, QVBoxLayout, QGridLayout,QTableWidget,QTableWidgetItem, QPushButton,QHeaderView, QLabel, QWidget, QAction, QFileDialog, QMessageBox, QInputDialog, QLineEdit)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtWidgets import QFileDialog
from PIL import Image, ImageSequence
def resource_path(relative_path):
    """Získá správnou cestu k resource souborům i po zabalení pomocí PyInstaller."""
    try:
        base_path = sys._MEIPASS  # PyInstaller temporary folder
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Nastavení AppUserModelID pro Windows
if platform.system() == "Windows":
    myappid = 'SecureDataSuite.1.0'  # Unikátní ID pro aplikaci
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

# Pokud jsme na Windows, importujeme potřebné moduly pro práci s Windows API
if os.name == 'nt':
    import win32gui
    import win32con
    import win32api

def make_window_transparent(screen, colorkey):
    """
    Nastaví oknu (vytvořenému přes pygame) průhlednou oblast definovanou colorkey.
    Funguje pouze na Windows.
    """
    hwnd = pygame.display.get_wm_info()["window"]
    # Získáme aktuální extenzivní styl okna a přidáme WS_EX_LAYERED
    ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
    win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE, ex_style | win32con.WS_EX_LAYERED)
    # Nastavíme colorkey jako průhlednou barvu
    # Win32 API očekává barvu jako integer vytvořený funkcí RGB
    win32gui.SetLayeredWindowAttributes(hwnd, win32api.RGB(*colorkey), 0, win32con.LWA_COLORKEY)

def play_intro_animation():
    pygame.init()

    # Nastavení rozměrů okna
    screen_width, screen_height = 620, 380

    # Vytvoření okna bez rámu
    screen = pygame.display.set_mode((screen_width, screen_height), pygame.NOFRAME)
    pygame.display.set_caption("Secure Data Suite")

    # Definujeme si unikátní barvu, kterou chceme mít jako transparentní (magenta)
    TRANSPARENT_COLOR = (255, 0, 255)
    # Vyplníme okno touto barvou – tato barva bude po nastavení colorkey systémem okna průhledná
    screen.fill(TRANSPARENT_COLOR)

    # Pokud jsme na Windows, nastavíme colorkey pro okno
    if os.name == 'nt':
        make_window_transparent(screen, TRANSPARENT_COLOR)
    else:
        print("Pozor: Průhlednost okna je nastavitelná pouze na Windows.")

    # Načtení videa a zvuku
    video_path = resource_path("startup.mp4")  # Nahraď vlastním umístěním videa
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print("Error: Could not open video file.")
        return

    # Předpokládané FPS
    fps = 60
    frame_duration = 1 / fps

    # Načtení zvuku
    sound_path =  resource_path("startup.wav") 
    sound = pygame.mixer.Sound(sound_path)  # Nahraď vlastním umístěním zvuku

    clock = pygame.time.Clock()
    running = True
    start_time = pygame.time.get_ticks()
    delay = 50  # prodleva pro spuštění zvuku (ms)
    audio_started = False

    # Vytvoříme masku – povrch, kde je vykreslen plně neprůhledný kruh uprostřed
    mask_surface = pygame.Surface((screen_width, screen_height), pygame.SRCALPHA)
    mask_surface.fill((0, 0, 0, 0))  # celý povrch transparentní
    # Nakreslíme bílý (alfa=255) kruh, kde chceme zobrazit video
    pygame.draw.circle(mask_surface, (255, 255, 255, 255),
                       (screen_width // 1.98, screen_height // 1.85), screen_width // 4.85)

    while running:
        ret, frame = cap.read()
        if not ret:  # Konec videa
            break

        # Změníme velikost snímku, aby odpovídal rozměrům okna
        frame = cv2.resize(frame, (screen_width, screen_height))
        # Otočíme snímek, aby byl správně orientován
        frame = cv2.transpose(frame)
        #frame = cv2.flip(frame, flipCode=0)

        # Spustíme zvuk s prodlevou
        if not audio_started and pygame.time.get_ticks() - start_time >= delay:
            sound.play()
            audio_started = True

        # Převod barev z BGR na RGB
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        # Vytvoříme povrch z dat snímku a zajistíme, aby měl alfa kanál
        frame_surface = pygame.surfarray.make_surface(frame).convert_alpha()

        # Aplikujeme kruhovou masku – mimo kruh budou pixely mít alfa 0 (tedy budou průhledné)
        frame_surface.blit(mask_surface, (0, 0), special_flags=pygame.BLEND_RGBA_MULT)

        # Vyplníme celé okno průhlednou barvou (colorkey)
        screen.fill(TRANSPARENT_COLOR)
        # Vykreslíme video snímek (maskovaný)
        screen.blit(frame_surface, (0, 0))

        pygame.display.flip()
        clock.tick(fps)

        # Zpracování událostí (například pro zavření okna)
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

    # Úklid
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
        self.setWindowIcon(QIcon(resource_path("icon.ico")))  # Ikona aplikace (musí být ve formátu .ico)

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
        pixmap = QPixmap(resource_path("banner.png"))  # Načtení obrázku
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
        new_password, ok = QInputDialog.getText(self, "Set main password", "Set new main password (min. 8 characters):", QLineEdit.Password)

        if not ok:  # Pokud uživatel stiskl "Cancel"
            return

        if len(new_password) < 8:
            QMessageBox.warning(self, "Error", "Password must be at least 8 characters long.")
        else:
            self.save_master_password(new_password)
            QMessageBox.information(self, "Success", "New password was successfully set.")

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
        
    def password_manager(self):
        self.password_manager_window = PasswordManagerApp(self)
        self.password_manager_window.show()

        
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

    try:
        file_ext = file_path.lower()

        # --- PDF METADATA SCRUBBING ---
        if file_ext.endswith('.pdf'):
            reader = PdfReader(file_path)
            scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed.pdf"

            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)  # Copy each page

            # Remove metadata
            writer.add_metadata({})  

            with open(scrubbed_file_path, "wb") as f_out:
                writer.write(f_out)

        # --- IMAGE METADATA SCRUBBING ---
        elif file_ext.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
            with Image.open(file_path) as img:
                scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed{os.path.splitext(file_path)[1]}"
                img.save(scrubbed_file_path, format=img.format)  # Saves without metadata

        # --- TEXT FILE METADATA SCRUBBING ---
        elif file_ext.endswith('.txt'):
            scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed.txt"
            with open(file_path, "r", encoding="utf-8") as original, open(scrubbed_file_path, "w", encoding="utf-8") as scrubbed:
                scrubbed.write(original.read())  # Copy content into a fresh file (removing metadata)

        else:
            raise ValueError("Unsupported file type for metadata scrubbing.")

        return scrubbed_file_path

    except Exception as e:
        import traceback
        print("Error:\n", traceback.format_exc())
        raise
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


def load_password() -> str:
    """Load the password from the file."""
    with open(PASSWORD_FILE, "r") as f:
        return f.read().strip()


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
            saved_password = load_password()
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
            password = load_password()
            key = get_key_from_password(password)
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
            password = load_password()
            key = get_key_from_password(password)
            try:
                decrypted_path = decrypt_file(file_path, key)
                QMessageBox.information(
                    self, "Success", f"File decrypted successfully! Saved at: {decrypted_path}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

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

    def get_encryption_key(self):
        """Retrieve the encryption key derived from the master password."""
        password = load_password()
        return get_key_from_password(password)

    def encrypt_text(self, plaintext, key):
        """Encrypt text using AES encryption."""
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode()

    def decrypt_text(self, encrypted_text, key):
        """Decrypt text using AES decryption."""
        try:
            data = base64.b64decode(encrypted_text)
            iv = data[:AES.block_size]
            ciphertext = data[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        except (ValueError, KeyError) as e:
            raise ValueError("Decryption failed. Incorrect data or key.")

    def add_password(self):
        if not self.parent().verify_master_password():
            return

        website, ok1 = QInputDialog.getText(self, "Add Password", "Enter Website/App:")
        if not ok1 or not website.strip():
            return

        password, ok2 = QInputDialog.getText(self, "Add Password", "Enter Password:", QLineEdit.Password)
        if not ok2 or not password.strip():
            return

        try:
            # Encrypt and save the password
            key = self.get_encryption_key()
            encrypted_password = self.encrypt_text(password.strip(), key)

            # Write to file
            with open("passwords.txt", "a", encoding="utf-8") as f:
                f.write(f"{website.strip()}|{encrypted_password}\n")

            QMessageBox.information(self, "Success", "Password added successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add password: {str(e)}")
            

    def load_passwords(self):
        if not self.parent().verify_master_password():
            return

        try:
            # Load and decrypt passwords from the file
            key = self.get_encryption_key()
            with open("passwords.txt", "r", encoding="utf-8") as f:
                self.table.setRowCount(0)
                for line in f:
                    if not line.strip():
                        continue  # Skip empty lines

                    try:
                        website, encrypted_password = line.strip().split("|", 1)
                        decrypted_password = self.decrypt_text(encrypted_password, key)

                        row_position = self.table.rowCount()
                        self.table.insertRow(row_position)
                        self.table.setItem(row_position, 0, QTableWidgetItem(website))
                        self.table.setItem(row_position, 1, QTableWidgetItem(decrypted_password))
                    except ValueError as e:
                        print(f"Skipping invalid entry: {line.strip()} - {str(e)}")

            QMessageBox.information(self, "Success", "Passwords loaded successfully!")
        except FileNotFoundError:
            QMessageBox.warning(self, "Warning", "No passwords found to load.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load passwords: {str(e)}")
  

# RUN #
if __name__ == "__main__":
    # Play intro animation
    play_intro_animation()

    app = QApplication(sys.argv)
    window = SecureDataSuite()
    window.show()
    print("Start time: ", time.time()- start )
    sys.exit(app.exec())