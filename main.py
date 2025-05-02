import os
import time
import sys
import threading
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QLabel, QPushButton,
                            QVBoxLayout, QHBoxLayout, QGridLayout, QLineEdit, QTextEdit, QListWidget,
                            QFileDialog, QFrame, QGroupBox, QMessageBox, QScrollArea, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

# ---------- Symmetric Encryption Layer ----------
def generate_symmetric_key():
    return Fernet.generate_key()

def symmetric_encrypt(key, data):
    f = Fernet(key)
    if isinstance(data, str):
        return f.encrypt(data.encode())
    return f.encrypt(data)

def symmetric_decrypt(key, ciphertext):
    f = Fernet(key)
    decrypted = f.decrypt(ciphertext)
    try:
        return decrypted.decode()
    except UnicodeDecodeError:
        return decrypted  # Return as bytes if it's not text

# ---------- Asymmetric Encryption for Key Exchange ----------
def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    if isinstance(data, str):
        data = data.encode()
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ---------- RBAC Implementation ----------
class RBACSystem:
    def __init__(self):
        self.roles_permissions = {
            "admin": ["encrypt", "decrypt", "upload", "download"],
            "editor": ["encrypt", "upload"],
            "viewer": ["download"]
        }

        self.users = {
            "alice": {"role": "admin", "password": "alice123"},
            "bob": {"role": "viewer", "password": "bob123"},
            "charlie": {"role": "editor", "password": "charlie123"}
        }

    def authenticate(self, username, password):
        user = self.users.get(username)
        if user and user["password"] == password:
            return True
        return False

    def is_authorized(self, username, action):
        user = self.users.get(username)
        if not user:
            return False
        role = user["role"]
        return action in self.roles_permissions.get(role, [])

# ---------- Cloud Storage Simulation ----------
class CloudStorage:
    def __init__(self):
        self.storage = {}
        # Create a mock storage directory if it doesn't exist
        if not os.path.exists("cloud_storage"):
            os.makedirs("cloud_storage")

    def upload(self, filename, data):
        self.storage[filename] = data
        # Save to mock cloud storage
        with open(os.path.join("cloud_storage", filename), 'wb') as f:
            f.write(data)
        return True

    def download(self, filename):
        # Get from mock cloud storage
        try:
            with open(os.path.join("cloud_storage", filename), 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None

# ---------- GUI Application ----------
class CloudEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Setup main window
        self.setWindowTitle("Cloud Service Encryption Demo")
        self.setGeometry(100, 100, 1200, 700)

        # Main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Initialize systems
        self.rbac = RBACSystem()
        self.cloud = CloudStorage()

        # Cryptographic variables
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None
        self.current_user = None

        # Create tabs
        self.tab_control = QTabWidget()
        self.main_layout.addWidget(self.tab_control)

        self.tab_login = QWidget()
        self.tab_encryption = QWidget()
        self.tab_cloud = QWidget()
        self.tab_visualization = QWidget()

        self.tab_control.addTab(self.tab_login, "Login")
        self.tab_control.addTab(self.tab_encryption, "Encryption")
        self.tab_control.addTab(self.tab_cloud, "Cloud Storage")
        self.tab_control.addTab(self.tab_visualization, "Visualization")

        # Setup the tabs
        self.setup_login_tab()
        self.setup_encryption_tab()
        self.setup_cloud_tab()
        self.setup_visualization_tab()

        # Disable tabs until login
        self.tab_control.setTabEnabled(1, False)
        self.tab_control.setTabEnabled(2, False)
        self.tab_control.setTabEnabled(3, False)

        # Status bar - Enhanced to be more prominent
        self.status_bar = QStatusBar()
        self.status_bar.setMinimumHeight(40)  # Make it taller
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: #F0F0F0;
                border-top: 1px solid #CCCCCC;
                font-size: 14px;
                font-weight: bold;
            }
        """)
        self.setStatusBar(self.status_bar)
        self.show_status("Ready", is_error=False)

    def show_status(self, message, is_error=False):
        """Enhanced status message display with color coding for errors"""
        if is_error:
            self.status_bar.setStyleSheet("""
                QStatusBar {
                    background-color: #FFEBEE;
                    color: #D32F2F;
                    border-top: 2px solid #D32F2F;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 3px;
                }
            """)
        else:
            self.status_bar.setStyleSheet("""
                QStatusBar {
                    background-color: #F0F0F0;
                    color: #2E7D32;
                    border-top: 1px solid #CCCCCC;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 3px;
                }
            """)
        self.status_bar.showMessage(f"Status: {message}")
        # Make sure the status bar is visible
        self.status_bar.setVisible(True)

    def setup_login_tab(self):
        layout = QVBoxLayout(self.tab_login)

        # Title
        title_label = QLabel("Secure Cloud Storage Login")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # Form layout for login
        form_layout = QGridLayout()
        layout.addLayout(form_layout)

        # Username
        form_layout.addWidget(QLabel("Username:"), 0, 0)
        self.username_field = QLineEdit()
        form_layout.addWidget(self.username_field, 0, 1)

        # Password
        form_layout.addWidget(QLabel("Password:"), 1, 0)
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.password_field, 1, 1)

        # Login button
        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)
        layout.addWidget(login_button)

        # Available users for demo
        users_group = QGroupBox("Available Users for Demo")
        users_layout = QVBoxLayout(users_group)

        users_layout.addWidget(QLabel("Username: alice, Password: alice123, Role: admin"))
        users_layout.addWidget(QLabel("Username: bob, Password: bob123, Role: viewer"))
        users_layout.addWidget(QLabel("Username: charlie, Password: charlie123, Role: editor"))

        layout.addWidget(users_group)
        layout.addStretch(1)  # Add stretch to push content to the top

    def setup_encryption_tab(self):
        layout = QVBoxLayout(self.tab_encryption)

        # Key generation section
        key_group = QGroupBox("Key Management")
        key_layout = QHBoxLayout(key_group)

        generate_button = QPushButton("Generate Keys")
        generate_button.clicked.connect(self.generate_keys)
        key_layout.addWidget(generate_button)

        key_layout.addWidget(QLabel("Status:"))
        self.key_status_label = QLabel("No keys generated")
        key_layout.addWidget(self.key_status_label)
        key_layout.addStretch(1)

        layout.addWidget(key_group)

        # Text encryption section
        encrypt_group = QGroupBox("Encrypt/Decrypt Text")
        encrypt_layout = QVBoxLayout(encrypt_group)

        encrypt_layout.addWidget(QLabel("Enter text to encrypt:"))
        self.plaintext = QTextEdit()
        encrypt_layout.addWidget(self.plaintext)

        button_layout = QHBoxLayout()
        encrypt_button = QPushButton("Encrypt")
        encrypt_button.clicked.connect(self.encrypt_text)
        button_layout.addWidget(encrypt_button)

        decrypt_button = QPushButton("Decrypt")
        decrypt_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(decrypt_button)
        button_layout.addStretch(1)

        encrypt_layout.addLayout(button_layout)

        encrypt_layout.addWidget(QLabel("Encrypted/Decrypted result:"))
        self.ciphertext = QTextEdit()
        encrypt_layout.addWidget(self.ciphertext)

        layout.addWidget(encrypt_group)

    def setup_cloud_tab(self):
        layout = QVBoxLayout(self.tab_cloud)

        # File upload section
        upload_group = QGroupBox("File Upload")
        upload_layout = QGridLayout(upload_group)

        upload_layout.addWidget(QLabel("Select file to upload:"), 0, 0)
        self.selected_file_field = QLineEdit()
        upload_layout.addWidget(self.selected_file_field, 0, 1)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        upload_layout.addWidget(browse_button, 0, 2)

        upload_button = QPushButton("Upload Encrypted")
        upload_button.clicked.connect(self.upload_file)
        upload_layout.addWidget(upload_button, 1, 0, 1, 3)

        layout.addWidget(upload_group)

        # File download section
        download_group = QGroupBox("File Download")
        download_layout = QVBoxLayout(download_group)

        download_layout.addWidget(QLabel("Available files:"))
        self.file_listbox = QListWidget()
        download_layout.addWidget(self.file_listbox)

        button_layout = QHBoxLayout()

        refresh_button = QPushButton("Refresh List")
        refresh_button.clicked.connect(self.refresh_file_list)
        button_layout.addWidget(refresh_button)

        download_button = QPushButton("Download & Decrypt")
        download_button.clicked.connect(self.download_file)
        button_layout.addWidget(download_button)
        button_layout.addStretch(1)

        download_layout.addLayout(button_layout)
        layout.addWidget(download_group)

        # Cloud storage contents
        cloud_group = QGroupBox("Cloud Storage Contents")
        cloud_layout = QVBoxLayout(cloud_group)

        self.cloud_files = QTextEdit()
        self.cloud_files.setReadOnly(True)
        self.cloud_files.setText("Cloud Storage Contents:\n")
        cloud_layout.addWidget(self.cloud_files)

        layout.addWidget(cloud_group)

        # Initial refresh
        self.refresh_file_list()

    def setup_visualization_tab(self):
        layout = QVBoxLayout(self.tab_visualization)

        # Create a label to display the encryption process image
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.image_label)

        # Display explanation text
        explanation = QTextEdit()
        explanation.setReadOnly(True)
        explanation.setMaximumHeight(150)
        # explanation.setText("""
        # Cloud Encryption Process Flow:

        # 1. User authentication verifies identity
        # 2. RBAC determines access permissions
        # 3. Symmetric keys encrypt the actual data
        # 4. Asymmetric keys securely exchange the symmetric key
        # 5. Files are encrypted before storage
        # 6. Only authorized users can decrypt and access files
        # """)
        layout.addWidget(explanation)

        # Load and display the image
        # Note: You would need to provide an actual image file in your application
        try:
            from PyQt5.QtGui import QPixmap
            pixmap = QPixmap("encryption_diagram.png")
            if not pixmap.isNull():
                self.image_label.setPixmap(pixmap.scaled(800, 500, Qt.KeepAspectRatio))
            else:
                self.image_label.setText("Encryption process diagram image not found.\nPlease add 'encryption_diagram.png' to the application directory.")
        except Exception as e:
            self.image_label.setText(f"Error loading image: {str(e)}\nPlease add 'encryption_diagram.png' to the application directory.")

    def create_encryption_diagram(self):
        self.figure.clear()

        # Create flow diagram
        ax = self.figure.add_subplot(111)
        ax.axis('off')

        # Draw the diagram
        boxes = [
            (0.1, 0.8, 0.2, 0.1, "User\nAuthentication", "#C6E2FF"),
            (0.1, 0.6, 0.2, 0.1, "Access Control\n(RBAC)", "#FFD700"),
            (0.4, 0.7, 0.2, 0.1, "Symmetric Key\nGeneration", "#98FB98"),
            (0.4, 0.5, 0.2, 0.1, "Asymmetric\nKey Exchange", "#FFA07A"),
            (0.7, 0.8, 0.2, 0.1, "File\nEncryption", "#F08080"),
            (0.7, 0.6, 0.2, 0.1, "Secure\nStorage", "#9370DB"),
            (0.7, 0.4, 0.2, 0.1, "Encrypted\nDownload", "#87CEFA"),
            (0.4, 0.3, 0.2, 0.1, "Authorized\nDecryption", "#FFDAB9"),
            (0.1, 0.4, 0.2, 0.1, "Decrypted\nFile Access", "#7FFFD4")
        ]

        # Draw boxes
        for x, y, w, h, label, color in boxes:
            ax.add_patch(plt.Rectangle((x, y), w, h, fill=True, color=color, alpha=0.7))
            ax.text(x + w/2, y + h/2, label, ha='center', va='center', fontsize=9)

        # Draw arrows
        arrows = [
            (0.2, 0.8, 0.1, 0.7),  # User Auth -> RBAC
            (0.2, 0.65, 0.4, 0.7),  # RBAC -> Symmetric Key
            (0.5, 0.7, 0.5, 0.6),  # Symmetric Key -> Asymmetric Key
            (0.5, 0.65, 0.7, 0.8),  # Asymmetric Key -> Encryption
            (0.8, 0.8, 0.8, 0.7),  # Encryption -> Storage
            (0.8, 0.6, 0.8, 0.5),  # Storage -> Download
            (0.7, 0.45, 0.5, 0.35),  # Download -> Decryption
            (0.4, 0.35, 0.2, 0.45),  # Decryption -> File Access
            (0.3, 0.5, 0.1, 0.5)   # Asymmetric Key -> RBAC (permissions)
        ]

        for x1, y1, x2, y2 in arrows:
            ax.arrow(x1, y1, x2-x1, y2-y1, head_width=0.02, head_length=0.02, fc='black', ec='black')

        # Add title
        ax.text(0.5, 0.95, "Cloud Encryption Process Flow",
                ha='center', va='center', fontsize=14, fontweight='bold')

        # Add description
        description = """
        This diagram illustrates the secure cloud storage process:
        1. User authentication verifies identity
        2. RBAC determines access permissions
        3. Symmetric keys encrypt the actual data
        4. Asymmetric keys securely exchange the symmetric key
        5. Files are encrypted before storage
        6. Only authorized users can decrypt and access files
        """
        ax.text(0.5, 0.15, description, ha='center', va='center', fontsize=10,
                bbox=dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.8))

        self.canvas.draw()

    def login(self):
        username = self.username_field.text()
        password = self.password_field.text()

        if self.rbac.authenticate(username, password):
            self.current_user = username
            self.show_status(f"Logged in as {username} ({self.rbac.users[username]['role']})")

            # Enable appropriate tabs based on role
            self.tab_control.setTabEnabled(1, True)  # Everyone can see encryption
            self.tab_control.setTabEnabled(3, True)  # Everyone can see visualization

            # Check if user has cloud access
            if self.rbac.is_authorized(username, "upload") or self.rbac.is_authorized(username, "download"):
                self.tab_control.setTabEnabled(2, True)
            else:
                self.tab_control.setTabEnabled(2, False)

            # Switch to encryption tab
            self.tab_control.setCurrentIndex(1)

            # Generate keys automatically
            self.generate_keys()
        else:
            self.show_status("Login failed. Invalid username or password.", is_error=True)

    def generate_keys(self):
        if not self.current_user:
            self.show_status("Please login first.", is_error=True)
            return

        # Show a "working" status
        self.key_status_label.setText("Generating keys...")
        QApplication.processEvents()

        # Generate keys
        self.symmetric_key = generate_symmetric_key()
        self.private_key, self.public_key = generate_asymmetric_keys()

        # Simulate some processing time
        time.sleep(1)

        self.key_status_label.setText("Keys generated successfully!")
        self.show_status("Cryptographic keys generated and ready for use.")

    def encrypt_text(self):
        if not self.symmetric_key:
            self.show_status("Please generate keys first.", is_error=True)
            return

        if not self.rbac.is_authorized(self.current_user, "encrypt"):
            self.show_status(f"User {self.current_user} is not authorized to encrypt data.", is_error=True)
            return

        text = self.plaintext.toPlainText().strip()
        if not text:
            self.show_status("Please enter text to encrypt.", is_error=True)
            return

        # Encrypt the text
        encrypted = symmetric_encrypt(self.symmetric_key, text)

        # Display in base64 for readability
        self.ciphertext.clear()
        self.ciphertext.setText(base64.b64encode(encrypted).decode())

        self.show_status("Text encrypted successfully.")

    def decrypt_text(self):
        if not self.symmetric_key:
            self.show_status("Please generate keys first.", is_error=True)
            return

        if not self.rbac.is_authorized(self.current_user, "decrypt"):
            self.show_status(f"User {self.current_user} is not authorized to decrypt data.", is_error=True)
            return

        text = self.plaintext.toPlainText().strip()
        if not text:
            self.show_status("No encrypted text to decrypt.", is_error=True)
            return

        try:
            # Decrypt the text
            encrypted_bytes = base64.b64decode(text)
            decrypted = symmetric_decrypt(self.symmetric_key, encrypted_bytes)

            # Display
            self.ciphertext.clear()
            if isinstance(decrypted, str):
                self.ciphertext.setText(decrypted)
            else:
                self.ciphertext.setText(str(decrypted))

            self.show_status("Text decrypted successfully.")
        except Exception as e:
            self.show_status(f"Decryption error: {str(e)}", is_error=True)

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select File")
        if filename:
            self.selected_file_field.setText(filename)

    def upload_file(self):
        if not self.symmetric_key:
            self.show_status("Please generate keys first.", is_error=True)
            return

        if not self.rbac.is_authorized(self.current_user, "upload"):
            self.show_status(f"User {self.current_user} is not authorized to upload files.", is_error=True)
            return

        filename = self.selected_file_field.text()
        if not filename:
            self.show_status("Please select a file first.", is_error=True)
            return

        try:
            # Read file
            with open(filename, 'rb') as f:
                file_data = f.read()

            # Show progress status
            self.show_status(f"Encrypting file {os.path.basename(filename)}...")
            QApplication.processEvents()

            # Encrypt the file
            encrypted_data = symmetric_encrypt(self.symmetric_key, file_data)

            # Upload to cloud
            cloud_filename = f"{os.path.basename(filename)}.encrypted"
            self.cloud.upload(cloud_filename, encrypted_data)

            self.show_status(f"File {os.path.basename(filename)} encrypted and uploaded as {cloud_filename}")
            self.refresh_file_list()
        except Exception as e:
            self.show_status(f"Upload error: {str(e)}", is_error=True)

    def refresh_file_list(self):
        # Clear existing list
        self.file_listbox.clear()

        # Show files in cloud storage directory
        if os.path.exists("cloud_storage"):
            files = os.listdir("cloud_storage")
            for file in files:
                self.file_listbox.addItem(file)

        # Update cloud files text area
        self.cloud_files.clear()
        self.cloud_files.append("Cloud Storage Contents:\n")

        if os.path.exists("cloud_storage"):
            files = os.listdir("cloud_storage")
            if files:
                for i, file in enumerate(files, 1):
                    file_path = os.path.join("cloud_storage", file)
                    size = os.path.getsize(file_path)
                    self.cloud_files.append(f"{i}. {file} ({size} bytes)\n")
            else:
                self.cloud_files.append("No files in cloud storage.\n")

    def download_file(self):
        if not self.symmetric_key:
            self.show_status("Please generate keys first.", is_error=True)
            return

        if not self.rbac.is_authorized(self.current_user, "download"):
            self.show_status(f"User {self.current_user} is not authorized to download files.", is_error=True)
            return

        # Get selected file
        selected_items = self.file_listbox.selectedItems()
        if not selected_items:
            self.show_status("Please select a file to download.", is_error=True)
            return

        filename = selected_items[0].text()

        try:
            # Download the file
            self.show_status(f"Downloading file {filename}...")
            QApplication.processEvents()

            encrypted_data = self.cloud.download(filename)
            if not encrypted_data:
                self.show_status(f"File {filename} not found.", is_error=True)
                return

            # Decrypt the file
            self.show_status(f"Decrypting file {filename}...")
            QApplication.processEvents()

            try:
                decrypted_data = symmetric_decrypt(self.symmetric_key, encrypted_data)
            except Exception:
                # If it's not text, handle as binary
                decrypted_data = symmetric_decrypt(self.symmetric_key, encrypted_data)

            # Save the decrypted file
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Decrypted File",
                filename.replace('.encrypted', '.decrypted')
            )

            if save_path:
                with open(save_path, 'wb') as f:
                    if isinstance(decrypted_data, str):
                        f.write(decrypted_data.encode())
                    else:
                        f.write(decrypted_data)

                self.show_status(f"File {filename} downloaded and decrypted successfully.")
            else:
                self.show_status("File save cancelled.")
        except Exception as e:
            self.show_status(f"Download error: {str(e)}", is_error=True)

# Run the application
if __name__ == "__main__":
    # Create cloud storage directory if it doesn't exist
    if not os.path.exists("cloud_storage"):
        os.makedirs("cloud_storage")

    app = QApplication(sys.argv)
    window = CloudEncryptionApp()
    window.show()
    sys.exit(app.exec_())
