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
import re
import secrets
import string
import sqlite3
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from PyQt5.QtWidgets import (QApplication, QMainWindow, QHBoxLayout, QFileDialog, QVBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem, QPushButton, QHeaderView, QLabel, QWidget, QAction, QMessageBox, QInputDialog, QLineEdit)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QDateTime

def resource_path(relative_path):
    """Získá správnou cestu k resource souborům i po zabalení pomocí PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Nastavení AppUserModelID pro Windows
if platform.system() == "Windows":
    myappid = 'SecureDataSuite.1.0'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

if os.name == 'nt':
    import win32gui
    import win32con
    import win32api

def make_window_transparent(screen, colorkey):
    hwnd = pygame.display.get_wm_info()["window"]
    ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
    win32gui.SetWindowLong(hwnd, win32con.GWL_EXSTYLE, ex_style | win32con.WS_EX_LAYERED)
    win32gui.SetLayeredWindowAttributes(hwnd, win32api.RGB(*colorkey), 0, win32con.LWA_COLORKEY)

def play_intro_animation():
    pygame.init()
    screen_width, screen_height = 620, 380
    screen = pygame.display.set_mode((screen_width, screen_height), pygame.NOFRAME)
    pygame.display.set_caption("Secure Data Suite")
    TRANSPARENT_COLOR = (255, 0, 255)
    screen.fill(TRANSPARENT_COLOR)
    if os.name == 'nt':
        make_window_transparent(screen, TRANSPARENT_COLOR)
    else:
        print("Pozor: Průhlednost okna je nastavitelná pouze na Windows.")

    video_path = resource_path("startup.mp4")
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print("Error: Could not open video file.")
        return

    fps = 60
    frame_duration = 1 / fps
    sound_path = resource_path("startup.wav")
    sound = pygame.mixer.Sound(sound_path)
    clock = pygame.time.Clock()
    running = True
    start_time = pygame.time.get_ticks()
    delay = 50
    audio_started = False
    mask_surface = pygame.Surface((screen_width, screen_height), pygame.SRCALPHA)
    mask_surface.fill((0, 0, 0, 0))
    pygame.draw.circle(mask_surface, (255, 255, 255, 255), (screen_width // 1.98, screen_height // 1.85), screen_width // 4.85)

    while running:
        ret, frame = cap.read()
        if not ret:
            break
        frame = cv2.resize(frame, (screen_width, screen_height))
        frame = cv2.transpose(frame)
        if not audio_started and pygame.time.get_ticks() - start_time >= delay:
            sound.play()
            audio_started = True
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame_surface = pygame.surfarray.make_surface(frame).convert_alpha()
        frame_surface.blit(mask_surface, (0, 0), special_flags=pygame.BLEND_RGBA_MULT)
        screen.fill(TRANSPARENT_COLOR)
        screen.blit(frame_surface, (0, 0))
        pygame.display.flip()
        clock.tick(fps)
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
    cap.release()
    pygame.quit()
    cv2.destroyAllWindows()

class SecureDataSuite(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureData Suite")
        self.setGeometry(700, 400, 600, 400)
        self.setWindowIcon(QIcon(resource_path("icon.ico")))
        self.central_widget = QWidget()
        self.central_widget.setStyleSheet("background-color: #f0f0f0;")
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout()
        self.init_database()
        self.setup_menu()
        self.setup_info_section()
        self.setup_buttons()
        self.central_widget.setLayout(self.main_layout)
        self.is_dark_mode = False
        self.apply_theme()
        # Ochrana proti hrubou silou
        self.failed_attempts = 0
        self.lockout_time = 0

    def init_database(self):
        """Inicializuje SQLite databázi a vytvoří potřebné tabulky."""
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            # Tabulka pro master password
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt TEXT NOT NULL,
                    ciphertext TEXT NOT NULL
                )
            """)
            # Tabulka pro hesla
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    website TEXT PRIMARY KEY,
                    encrypted_password TEXT NOT NULL
                )
            """)
            conn.commit()
            conn.close()
            print("Databáze inicializována.")
        except Exception as e:
            print(f"Chyba při inicializaci databáze: {str(e)}")

    def setup_info_section(self):
        info_layout = QVBoxLayout()
        info_layout.setSpacing(0)
        info_layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(self)
        pixmap = QPixmap(resource_path("banner.png"))
        pixmap = pixmap.scaled(520, 220, Qt.KeepAspectRatio)
        label.setPixmap(pixmap)
        label.setAlignment(Qt.AlignCenter)
        info_layout.addWidget(label)
        description_label = QLabel("Spravujte své soubory a data bezpečně.")
        description_label.setAlignment(Qt.AlignCenter)
        description_label.setStyleSheet("font-size: 14px; margin: 10px;")
        info_layout.addWidget(description_label)
        self.main_layout.addLayout(info_layout)
        self.create_startup_log()

    def create_startup_log(self):
        try:
            with open("app_logs.txt", "a", encoding="utf-8") as file:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                file.write(f"Aplikace spuštěna v {timestamp}\n")
        except Exception as e:
            print(f"Chyba při zápisu do logu: {e}")

    def setup_buttons(self):
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
            if btn.text() == "File Shredder":
                btn.setToolTip("Bezpečně smaže vybrané soubory přepsáním a odstraněním.")
            elif btn.text() == "File Encryption":
                btn.setToolTip("Zašifruje nebo dešifruje vybrané soubory pomocí AES-256.")
            elif btn.text() == "Data Scrubber":
                btn.setToolTip("Odstraní metadata z vybraných souborů.")
            elif btn.text() == "Password Manager":
                btn.setToolTip("Spravuje vaše hesla bezpečně.")
        button_layout.addWidget(btn1, 0, 0)
        button_layout.addWidget(btn2, 0, 1)
        button_layout.addWidget(btn3, 1, 0)
        button_layout.addWidget(btn4, 1, 1)
        button_layout.setContentsMargins(50, 20, 50, 20)
        button_widget.setLayout(button_layout)
        self.main_layout.addWidget(button_widget, alignment=Qt.AlignCenter)

    def setup_menu(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("Soubor")
        file_menu.addAction(self.create_action("Otevřít soubor", self.open_file))
        file_menu.addAction(self.create_action("Uložit nastavení", self.save_settings))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action("Konec", self.close))
        tools_menu = menu_bar.addMenu("Nástroje")
        tools_menu.addAction(self.create_action("File Shredder", self.file_shredder))
        tools_menu.addAction(self.create_action("Data Scrubber", self.scrub_metadata))
        tools_menu.addAction(self.create_action("File Encryption", self.file_encryption))
        tools_menu.addAction(self.create_action("Password Manager", self.password_manager))
        settings_menu = menu_bar.addMenu("Nastavení")
        settings_menu.addAction(self.create_action("Nastavení šifrování", self.encryption_settings))
        settings_menu.addAction(self.create_action("Nastavení zálohování", self.backup_settings))
        settings_menu.addAction(self.create_action("Téma", self.toggle_theme))
        security_menu = menu_bar.addMenu("Bezpečnost")
        security_menu.addAction(self.create_action("Nastavit hlavní heslo", self.set_master_password))
        security_menu.addAction(self.create_action("Zobrazit logy", self.view_logs))
        security_menu.addAction(self.create_action("Vymazat logy", self.clear_logs))
        help_menu = menu_bar.addMenu("Nápověda")
        help_menu.addAction(self.create_action("Uživatelská příručka", self.user_guide))
        help_menu.addAction(self.create_action("O aplikaci", self.about))

    def create_action(self, name, handler):
        action = QAction(name, self)
        action.triggered.connect(handler)
        return action

    def open_file(self):
        QMessageBox.information(self, "Otevřít soubor", "Funkce ještě není implementována!")

    def save_settings(self):
        QMessageBox.information(self, "Uložit nastavení", "Funkce ještě není implementována!")

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
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM master_password WHERE id = 1")
            result = cursor.fetchone()
            conn.close()
            if not result:
                QMessageBox.warning(self, "Chyba", "Hlavní heslo není nastavené. Nejdřív ho nastavte.")
                return
        except Exception as e:
            print(f"Chyba při kontrole hlavního hesla: {str(e)}")
            QMessageBox.warning(self, "Chyba", "Nepodařilo se ověřit nastavení hlavního hesla.")
            return

        self.password_manager_window = PasswordManagerApp(self)
        self.password_manager_window.show()

    def encryption_settings(self):
        QMessageBox.information(self, "Nastavení šifrování", "Nastavte možnosti šifrování.")

    def backup_settings(self):
        QMessageBox.information(self, "Nastavení zálohování", "Nastavte možnosti zálohování.")

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_mode:
            dark_mode_stylesheet = """
            QMainWindow { background-color: #2b2b2b; }
            QWidget { background-color: #2b2b2b; color: #f0f0f0; }
            QPushButton { background-color: #444; color: #ffffff; border: 1px solid #555; padding: 5px; border-radius: 5px; }
            QPushButton:hover { background-color: #555; }
            QPushButton:pressed { background-color: #666; }
            QPushButton:disabled { background-color: #444; color: #888; }
            QLabel { color: #f0f0f0; }
            QMenuBar { background-color: #2b2b2b; color: #f0f0f0; }
            QMenuBar::item { background-color: #2b2b2b; color: #f0f0f0; }
            QMenuBar::item:selected { background-color: #444; }
            QMenu { background-color: #2b2b2b; color: #f0f0f0; }
            QMenu::item { background-color: #2b2b2b; color: #f0f0f0; }
            QMenu::item:selected { background-color: #444; }
            """
            self.setStyleSheet(dark_mode_stylesheet)
            self.central_widget.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        else:
            light_mode_stylesheet = """
            QMainWindow { background-color: #f0f0f0; }
            QWidget { background-color: #f0f0f0; color: #000000; }
            QPushButton { background-color: #444; color: #ffffff; border: 1px solid #555; padding: 5px; border-radius: 5px; }
            QPushButton:hover { background-color: #555; }
            QPushButton:pressed { background-color: #666; }
            QPushButton:disabled { background-color: #444; color: #888; }
            QLabel { color: #000000; }
            QMenuBar { background-color: #f0f0f0; color: #000000; }
            QMenuBar::item { background-color: #f0f0f0; color: #000000; }
            QMenuBar::item:selected { background-color: #444; }
            QMenu { background-color: #f0f0f0; color: #000000; }
            QMenu::item { background-color: #f0f0f0; color: #000000; }
            QMenu::item:selected { background-color: #444; }
            """
            self.setStyleSheet(light_mode_stylesheet)
            self.central_widget.setStyleSheet("background-color: #f0f0f0; color: #000000;")

    KNOWN_PLAINTEXT = b"SecureDataSuite"

    def set_master_password(self):
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("SELECT salt, ciphertext FROM master_password WHERE id = 1")
            result = cursor.fetchone()
            if result:
                current_password, ok = QInputDialog.getText(self, "Zadejte stávající heslo", "Stávající heslo:", QLineEdit.Password)
                if not ok:
                    print("Zrušeno zadání stávajícího hesla.")
                    conn.close()
                    return
                old_key = self.get_encryption_key_from_password(current_password)
                if not old_key:
                    QMessageBox.warning(self, "Chyba", "Nesprávné stávající heslo.")
                    print("Nesprávné stávající heslo zadáno.")
                    conn.close()
                    return
            else:
                old_key = None
        except Exception as e:
            print(f"Chyba při kontrole stávajícího hesla: {str(e)}")
            conn.close()
            return

        new_password, ok = QInputDialog.getText(self, "Nastavit hlavní heslo", "Zadejte nové hlavní heslo:", QLineEdit.Password)
        if not ok or not new_password:
            print("Zrušeno zadání nového hesla.")
            conn.close()
            return

        if not re.match(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_:])[A-Za-z\d@$!%*?&_áéíóúůýčďěňřšťžÁÉÍÓÚŮÝČĎĚŇŘŠŤŽ]{6,}$", new_password):
            QMessageBox.warning(self, "Chyba", "Heslo musí mít alespoň 6 znaků, jedno velké písmeno, jedno číslo a jeden speciální znak (@$!%*?&_:).")
            print("Neplatné heslo zadáno.")
            conn.close()
            return

        try:
            salt = get_random_bytes(16)
            key = PBKDF2(new_password.encode('utf-8'), salt, dkLen=32, count=600000, hmac_hash_module=SHA256)
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv
            ciphertext = cipher.encrypt(pad(self.KNOWN_PLAINTEXT, AES.block_size))
            full_ciphertext = iv + ciphertext

            cursor.execute("DELETE FROM master_password WHERE id = 1")
            cursor.execute(
                "INSERT INTO master_password (id, salt, ciphertext) VALUES (?, ?, ?)",
                (1, base64.b64encode(salt).decode('utf-8'), base64.b64encode(full_ciphertext).decode('utf-8'))
            )
            conn.commit()
            print("Hlavní heslo úspěšně uloženo do databáze.")
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Nastavení hesla selhalo: {str(e)}")
            print(f"Chyba při ukládání: {str(e)}")
            conn.close()
            return

        if old_key:
            try:
                cursor.execute("SELECT website, encrypted_password FROM passwords")
                rows = cursor.fetchall()
                new_rows = []
                for encrypted_website, encrypted_password in rows:
                    try:
                        website = self.decrypt_text(encrypted_website, old_key)
                        cipher = AES.new(old_key, AES.MODE_CBC)
                        iv = base64.b64decode(encrypted_password)[:16]
                        ciphertext = base64.b64decode(encrypted_password)[16:]
                        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
                    except Exception as e:
                        print(f"Chyba při dešifrování hesla: {e}")
                        continue
                    new_encrypted_website = self.encrypt_text(website, key)
                    cipher = AES.new(key, AES.MODE_CBC)
                    new_iv = cipher.iv
                    new_ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
                    new_full_ciphertext = new_iv + new_ciphertext
                    new_encrypted_password = base64.b64encode(new_full_ciphertext).decode('utf-8')
                    new_rows.append((new_encrypted_website, new_encrypted_password))
                cursor.execute("DELETE FROM passwords")
                for new_encrypted_website, new_encrypted_password in new_rows:
                    cursor.execute("INSERT INTO passwords (website, encrypted_password) VALUES (?, ?)", (new_encrypted_website, new_encrypted_password))
                conn.commit()
                print("Hesla v databázi přešifrována.")
            except Exception as e:
                QMessageBox.warning(self, "Varování", f"Přešifrování hesel selhalo: {str(e)}")
                print(f"Chyba při přešifrování: {str(e)}")

        conn.close()
        QMessageBox.information(self, "Úspěch", "Hlavní heslo bylo úspěšně nastaveno.")
        # Reset počtu pokusů po úspěšném nastavení hesla
        self.failed_attempts = 0
        self.lockout_time = 0

    def get_encryption_key_from_password(self, password):
        # Ochrana proti hrubou silou
        current_time = time.time()
        if self.lockout_time > current_time:
            QMessageBox.warning(self, "Blokováno", f"Příliš mnoho špatných pokusů. Zkuste to znovu za {int(self.lockout_time - current_time)} sekund.")
            return None
        if self.failed_attempts >= 5:
            self.lockout_time = current_time + 300  # Blokování na 5 minut
            QMessageBox.warning(self, "Blokováno", "Příliš mnoho špatných pokusů. Aplikace je zablokována na 5 minut.")
            return None

        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("SELECT salt, ciphertext FROM master_password WHERE id = 1")
            result = cursor.fetchone()
            conn.close()
            if not result:
                print("Hlavní heslo není nastaveno.")
                return None

            salt_b64, ciphertext_b64 = result
            salt = base64.b64decode(salt_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=600000, hmac_hash_module=SHA256)
            iv = ciphertext[:16]
            encrypted_data = ciphertext[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            if plaintext == self.KNOWN_PLAINTEXT:
                print("Heslo ověřeno úspěšně.")
                self.failed_attempts = 0  # Reset počtu pokusů po úspěšném ověření
                return key
            print("Heslo neodpovídá uloženému hash.")
            self.failed_attempts += 1
            return None
        except Exception as e:
            print(f"Chyba při ověření hesla: {str(e)}")
            self.failed_attempts += 1
            return None

    def verify_master_password(self):
        password, ok = QInputDialog.getText(self, "Ověření hesla", "Zadejte hlavní heslo:", QLineEdit.Password)
        if not ok or not password:
            print("Ověření hesla zrušeno.")
            return None
        key = self.get_encryption_key_from_password(password)
        if key:
            return key
        else:
            QMessageBox.warning(self, "Chyba", "Nesprávné hlavní heslo.")
            return None

    def view_logs(self):
        if self.verify_master_password():
            if not os.path.exists("app_logs.txt"):
                QMessageBox.warning(self, "Žádné logy", "Nenalezeny žádné logy.")
                return
            try:
                if sys.platform == "win32":
                    os.startfile("app_logs.txt")
                elif sys.platform == "darwin":
                    os.system("open app_logs.txt")
                else:
                    os.system("xdg-open app_logs.txt")
            except Exception as e:
                QMessageBox.warning(self, "Chyba", f"Nelze otevřít logy: {str(e)}")

    def clear_logs(self):
        if self.verify_master_password():
            try:
                open("app_logs.txt", "w", encoding="utf-8").close()
                QMessageBox.information(self, "Logy vymazány", "Logy byly úspěšně vymazány.")
            except FileNotFoundError:
                QMessageBox.warning(self, "Chyba", "Žádné logy k vymazání.")

    def user_guide(self):
        QMessageBox.information(self, "Uživatelská příručka",
                                "Vítejte v aplikaci SecureData Suite!\n\n"
                                "1. File Shredder: Bezpečně maže soubory přepsáním 3x a následným odstraněním.\n"
                                "2. File Encryption: Šifruje a dešifruje soubory pomocí AES-256.\n"
                                "3. Data Scrubber: Odstraňuje citlivá metadata ze souborů.\n"
                                "4. Password Manager: Spravuje hesla bezpečně.\n\n"
                                "Další funkce:\n"
                                "- V menu Nastavení můžete přepínat mezi tmavým a světlým režimem.\n\n"
                                "Vaše bezpečí je naše priorita 🔝")

    def about(self):
        QMessageBox.information(self, "O aplikaci", "SecureData Suite verze 1.0\nVyvinuto 1K")

    def encrypt_text(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

    def decrypt_text(self, encrypted_text, key):
        try:
            data = base64.b64decode(encrypted_text)
            iv = data[:AES.block_size]
            ciphertext = data[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
        except (ValueError, KeyError) as e:
            raise ValueError(f"Dešifrování selhalo: Nesprávná data nebo klíč. ({str(e)})")

class FileShredderApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Shredder")
        self.setGeometry(770, 600, 400, 200)
        self.label = QLabel("Vyberte soubor k bezpečnému smazání:", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 14px;")
        self.shred_button = QPushButton("Vybrat a smazat soubor", self)
        self.shred_button.clicked.connect(self.select_and_shred_file)
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.shred_button)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def select_and_shred_file(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Vyberte soubory", "", "Všechny soubory (*.*)")
        if file_paths:
            self.label.setText(f"Zpracovávám {len(file_paths)} soubor(ů)...")
            failed_files = []
            for file_path in file_paths:
                try:
                    self.shred_file(file_path)
                except Exception as e:
                    failed_files.append((file_path, str(e)))
            if failed_files:
                error_message = "\n".join([f"{file}: {error}" for file, error in failed_files])
                self.label.setText(f"Došlo k chybám:\n{error_message}")
            else:
                self.label.setText("Všechny soubory bezpečně smazány! 🤯")
                self.label.setStyleSheet("font-size: 25px; font-weight: bold;")

    def shred_file(self, file_path):
        file_size = os.path.getsize(file_path)
        with open(file_path, 'wb') as file:
            for _ in range(3):
                file.write(os.urandom(file_size))
                file.flush()
                os.fsync(file.fileno())
        os.remove(file_path)
        try:
            with open("app_logs.txt", "a", encoding="utf-8") as file:
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                file.write(f"Bezpečně smazáno: {file_path} v {timestamp}\n")
        except Exception as e:
            print(e)

def scrub_image_metadata(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Soubor '{file_path}' nebyl nalezen.")
    try:
        file_ext = file_path.lower()
        if file_ext.endswith('.pdf'):
            reader = PdfReader(file_path)
            scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed.pdf"
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({})
            with open(scrubbed_file_path, "wb") as f_out:
                writer.write(f_out)
        elif file_ext.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
            with Image.open(file_path) as img:
                scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed{os.path.splitext(file_path)[1]}"
                img.save(scrubbed_file_path, format=img.format)
        elif file_ext.endswith('.txt'):
            scrubbed_file_path = f"{os.path.splitext(file_path)[0]}_scrubbed.txt"
            with open(file_path, "r", encoding="utf-8") as original, open(scrubbed_file_path, "w", encoding="utf-8") as scrubbed:
                scrubbed.write(original.read())
        else:
            raise ValueError("Nepodporovaný typ souboru pro odstranění metadat.")
        return scrubbed_file_path
    except Exception as e:
        import traceback
        print("Chyba:\n", traceback.format_exc())
        raise

class FileMetadataScrubberApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Metadata Scrubber")
        self.setGeometry(770, 600, 400, 200)
        self.label = QLabel("Vyberte soubory k odstranění metadat:", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 14px;")
        self.scrub_button = QPushButton("Vybrat a odstranit metadata", self)
        self.scrub_button.clicked.connect(self.select_and_scrub_metadata)
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.scrub_button)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def select_and_scrub_metadata(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Vyberte soubory", "", "Všechny soubory (*.*)")
        if file_paths:
            for file_path in file_paths:
                try:
                    scrubbed_file_path = scrub_image_metadata(file_path)
                    self.label.setText("Metadata úspěšně odstraněna!🧽")
                    self.label.setStyleSheet("font-size: 25px; font-weight: bold;")
                except Exception as e:
                    self.label.setText(f"Chyba: {str(e)}")
                try:
                    with open("app_logs.txt", "a", encoding="utf-8") as file:
                        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                        file.write(f"Metadata bezpečně odstraněna: {file_path} v {timestamp}\n")
                except Exception as e:
                    print(e)

def get_key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(cipher.iv + ciphertext)
    return encrypted_path

def decrypt_file(file_path, key):
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

class FileEncrypterApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Encryption")
        self.setGeometry(770, 600, 400, 300)
        self.label = QLabel("Vyberte soubor k zašifrování nebo dešifrování:", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 14px;")
        self.encrypt_button = QPushButton("Zašifrovat soubor", self)
        self.decrypt_button = QPushButton("Dešifrovat soubor", self)
        self.encrypt_button.clicked.connect(self.encrypt_file_action)
        self.decrypt_button.clicked.connect(self.decrypt_file_action)
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def encrypt_file_action(self):
        key = self.parent().verify_master_password()
        if not key:
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Vyberte soubor k zašifrování")
        if file_path:
            try:
                encrypted_path = encrypt_file(file_path, key)
                QMessageBox.information(self, "Úspěch", f"Soubor úspěšně zašifrován! Uložen jako: {encrypted_path}")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", f"Šifrování selhalo: {str(e)}")

    def decrypt_file_action(self):
        key = self.parent().verify_master_password()
        if not key:
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Vyberte soubor k dešifrování")
        if file_path:
            try:
                decrypted_path = decrypt_file(file_path, key)
                QMessageBox.information(self, "Úspěch", f"Soubor úspěšně dešifrován! Uložen jako: {decrypted_path}")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", f"Dešifrování selhalo: {str(e)}")

class PasswordManagerApp(QMainWindow):
    def __init__(self, parent):
        super().__init__(parent)
        self.encryption_key = None
        self.passwords = {}  # Dešifrovaná hesla (website: password)
        self.encrypted_passwords = {}  # Šifrovaná hesla (website: encrypted_password)
        self.encrypted_websites = {}  # Mapování dešifrovaného webu na šifrovaný (website: encrypted_website)
        self.setWindowTitle("Password Manager")
        self.setGeometry(700, 400, 600, 500)

        # Centrální widget a hlavní layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)

        # Nadpis
        self.label = QLabel("Správce hesel")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        self.main_layout.addWidget(self.label)

        # Tabulka
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Web/Aplikace", "Heslo", "Akce"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self.table.horizontalHeader().setMinimumSectionSize(100)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self.copy_password)
        self.table.setMinimumHeight(300)
        self.main_layout.addWidget(self.table)

        # Tlačítka
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        self.add_button = QPushButton("Přidat heslo")
        self.add_button.clicked.connect(self.add_password)
        self.add_button.setFixedSize(150, 40)
        self.add_button.setStyleSheet("""
            QPushButton { background-color: #444; color: #fff; font-size: 14px; border-radius: 5px; }
            QPushButton:hover { background-color: #555; }
            QPushButton:pressed { background-color: #666; }
        """)
        button_layout.addWidget(self.add_button)

        self.generate_button = QPushButton("Generovat heslo")
        self.generate_button.clicked.connect(self.generate_password)
        self.generate_button.setFixedSize(150, 40)
        self.generate_button.setStyleSheet("""
            QPushButton { background-color: #444; color: #fff; font-size: 14px; border-radius: 5px; }
            QPushButton:hover { background-color: #555; }
            QPushButton:pressed { background-color: #666; }
        """)
        button_layout.addWidget(self.generate_button)

        self.show_button = QPushButton("Zobrazit hesla")
        self.show_button.clicked.connect(self.show_passwords)
        self.show_button.setFixedSize(150, 40)
        self.show_button.setStyleSheet("""
            QPushButton { background-color: #444; color: #fff; font-size: 14px; border-radius: 5px; }
            QPushButton:hover { background-color: #555; }
            QPushButton:pressed { background-color: #666; }
        """)
        button_layout.addWidget(self.show_button)

        self.delete_button = QPushButton("Smazat vybrané")
        self.delete_button.clicked.connect(self.delete_selected_passwords)
        self.delete_button.setFixedSize(150, 40)
        self.delete_button.setStyleSheet("""
            QPushButton { background-color: #444; color: #fff; font-size: 14px; border-radius: 5px; }
            QPushButton:hover { background-color: #555; }
            QPushButton:pressed { background-color: #666; }
        """)
        button_layout.addWidget(self.delete_button)

        self.main_layout.addLayout(button_layout)
        self.load_websites()

    def load_websites(self):
        """Načte hesla z databáze a naplní tabulku."""
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("SELECT website, encrypted_password FROM passwords")
            rows = cursor.fetchall()
            self.table.setRowCount(0)
            self.encrypted_passwords.clear()
            self.encrypted_websites.clear()
            if not self.encryption_key:
                key = self.parent().verify_master_password()
                if not key:
                    conn.close()
                    return
                self.encryption_key = key

            for encrypted_website, encrypted_password in rows:
                try:
                    website = self.parent().decrypt_text(encrypted_website, self.encryption_key)
                except Exception as e:
                    print(f"Chyba při dešifrování webu: {str(e)}")
                    continue
                self.encrypted_websites[website] = encrypted_website
                self.encrypted_passwords[website] = encrypted_password
                row_position = self.table.rowCount()
                self.table.insertRow(row_position)
                self.table.setItem(row_position, 0, QTableWidgetItem(website))
                self.table.setItem(row_position, 1, QTableWidgetItem("••••••"))
                show_button = QPushButton("Zobrazit")
                show_button.setStyleSheet("""
                    QPushButton { background-color: #555; color: #fff; font-size: 12px; border-radius: 3px; }
                    QPushButton:hover { background-color: #666; }
                    QPushButton:pressed { background-color: #777; }
                """)
                show_button.clicked.connect(lambda checked, row=row_position: self.show_password(row))
                self.table.setCellWidget(row_position, 2, show_button)
            conn.close()
        except Exception as e:
            print(f"Chyba při načítání hesel z databáze: {str(e)}")

    def show_passwords(self):
        if not self.encryption_key:
            key = self.parent().verify_master_password()
            if not key:
                return
            self.encryption_key = key

        if not self.encrypted_passwords:
            QMessageBox.information(self, "Info", "Žádná hesla nejsou uložena. Můžete přidat nové.")
        else:
            try:
                self.passwords.clear()
                for website, encrypted_password in self.encrypted_passwords.items():
                    decrypted_password = self.parent().decrypt_text(encrypted_password, self.encryption_key)
                    self.passwords[website] = decrypted_password
                QMessageBox.information(self, "Úspěch", "Hesla byla načtena a jsou připravena ke kopírování nebo zobrazení.")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", f"Nepodařilo se dešifrovat hesla: {str(e)}")
                self.passwords.clear()
                self.encryption_key = None

    def generate_password(self):
        length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        while not re.match(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_:])[A-Za-z\d@$!%*?&_áéíóúůýčďěňřšťžÁÉÍÓÚŮÝČĎĚŇŘŠŤŽ]{6,}$", password):
            password = ''.join(secrets.choice(characters) for _ in range(length))
        QMessageBox.information(self, "Vygenerované heslo", f"Vygenerované heslo: {password}\nZkopírujte si ho nebo použijte při přidání nového hesla.")
        QApplication.clipboard().setText(password)

    def add_password(self):
        if not self.encryption_key:
            key = self.parent().verify_master_password()
            if not key:
                return
            self.encryption_key = key

        website, ok1 = QInputDialog.getText(self, "Přidat heslo", "Zadejte web/aplikaci:")
        if not ok1 or not website.strip():
            return
        if website in self.passwords:
            reply = QMessageBox.question(self, "Web už existuje", "Heslo pro tento web už existuje. Přepsat?", QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return
            else:
                encrypted_website = self.encrypted_websites.get(website)
                if encrypted_website:
                    try:
                        conn = sqlite3.connect("passwords.db")
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM passwords WHERE website = ?", (encrypted_website,))
                        conn.commit()
                        conn.close()
                        del self.passwords[website]
                        del self.encrypted_passwords[website]
                        del self.encrypted_websites[website]
                    except Exception as e:
                        print(f"Chyba při mazání hesla z databáze: {str(e)}")
                        return

        password, ok2 = QInputDialog.getText(self, "Přidat heslo", "Zadejte heslo (nebo použijte vygenerované):", QLineEdit.Password)
        if not ok2 or not password.strip():
            return

        if not re.match(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_:])[A-Za-z\d@$!%*?&_áéíóúůýčďěňřšťžÁÉÍÓÚŮÝČĎĚŇŘŠŤŽ]{6,}$", password):
            QMessageBox.warning(self, "Chyba", "Heslo musí mít alespoň 6 znaků, jedno velké písmeno, jedno číslo a jeden speciální znak (@$!%*?&_:).")
            return

        encrypted_website = self.parent().encrypt_text(website.strip(), self.encryption_key)
        encrypted_password = self.parent().encrypt_text(password.strip(), self.encryption_key)
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO passwords (website, encrypted_password) VALUES (?, ?)", (encrypted_website, encrypted_password))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Chyba při ukládání hesla do databáze: {str(e)}")
            return

        self.passwords[website] = password.strip()
        self.encrypted_passwords[website] = encrypted_password
        self.encrypted_websites[website] = encrypted_website
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        self.table.setItem(row_position, 0, QTableWidgetItem(website))
        self.table.setItem(row_position, 1, QTableWidgetItem("••••••"))
        show_button = QPushButton("Zobrazit")
        show_button.setStyleSheet("""
            QPushButton { background-color: #555; color: #fff; font-size: 12px; border-radius: 3px; }
            QPushButton:hover { background-color: #666; }
            QPushButton:pressed { background-color: #777; }
        """)
        show_button.clicked.connect(lambda checked, row=row_position: self.show_password(row))
        self.table.setCellWidget(row_position, 2, show_button)
        QMessageBox.information(self, "Úspěch", "Heslo bylo přidáno!")

    def show_password(self, row):
        if not self.encryption_key:
            QMessageBox.warning(self, "Chyba", "Nejprve načtěte hesla zadáním hlavního hesla.")
            return
        website = self.table.item(row, 0).text()
        if website in self.passwords:
            QMessageBox.information(self, "Heslo", f"Heslo pro {website}: {self.passwords[website]}")
        else:
            QMessageBox.warning(self, "Chyba", "Heslo nenalezeno.")

    def copy_password(self, row, column):
        if column == 1:
            if not self.encryption_key:
                QMessageBox.warning(self, "Chyba", "Nejprve načtěte hesla zadáním hlavního hesla.")
                return
            website = self.table.item(row, 0).text()
            if website in self.passwords:
                QApplication.clipboard().setText(self.passwords[website])
                QMessageBox.information(self, "Zkopírováno", "Heslo bylo zkopírováno do schránky.")
            else:
                QMessageBox.warning(self, "Chyba", "Heslo nenalezeno.")

    def delete_selected_passwords(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Varování", "Nejsou vybrány žádné řádky.")
            return
        reply = QMessageBox.question(self, "Potvrdit smazání", "Opravdu chcete smazat vybraná hesla?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            websites_to_delete = [self.table.item(row.row(), 0).text() for row in selected_rows]
            try:
                conn = sqlite3.connect("passwords.db")
                cursor = conn.cursor()
                for website in websites_to_delete:
                    encrypted_website = self.encrypted_websites.get(website)
                    if encrypted_website:
                        cursor.execute("DELETE FROM passwords WHERE website = ?", (encrypted_website,))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Chyba při mazání hesel z databáze: {str(e)}")
                return

            for row in sorted([r.row() for r in selected_rows], reverse=True):
                website = self.table.item(row, 0).text()
                if website in self.passwords:
                    del self.passwords[website]
                if website in self.encrypted_passwords:
                    del self.encrypted_passwords[website]
                if website in self.encrypted_websites:
                    del self.encrypted_websites[website]
                self.table.removeRow(row)
            QMessageBox.information(self, "Úspěch", "Vybraná hesla byla smazána.")

if __name__ == "__main__":
    play_intro_animation()
    app = QApplication(sys.argv)
    window = SecureDataSuite()
    window.show()
    print("Čas spuštění: ", time.time() - start)
    sys.exit(app.exec())