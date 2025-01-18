import os
import random
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton, QLabel, QVBoxLayout, QWidget

class FileShredderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Shredder")
        self.setGeometry(100, 100, 400, 200)

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
            except Exception as e:
                self.label.setText(f"Chyba: {str(e)}")

    def shred_file(self, file_path):
        """Přepisuje a maže soubor"""
        file_size = os.path.getsize(file_path)

        with open(file_path, 'wb') as file:
            for _ in range(3):  # Přepište 3x náhodnými daty
                file.write(os.urandom(file_size))
                file.flush()
                os.fsync(file.fileno())

        os.remove(file_path)  # Smažte soubor

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileShredderApp()
    window.show()
    sys.exit(app.exec())
