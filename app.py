import os
import base64
import secrets
import time
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
from io import BytesIO
import base64 as b64

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['KEYS_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
app.config['CLOUD_STORAGE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloud_storage')

# Create required directories if they don't exist
for directory in [app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], app.config['CLOUD_STORAGE']]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# ---------- Symmetric Encryption Layer ----------
def generate_symmetric_key():
    key = Fernet.generate_key()
    # Save key to file
    with open(os.path.join(app.config['KEYS_FOLDER'], 'symmetric_key.key'), 'wb') as key_file:
        key_file.write(key)
    return key

def get_symmetric_key():
    key_path = os.path.join(app.config['KEYS_FOLDER'], 'symmetric_key.key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    return generate_symmetric_key()

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
    
    # For simplicity in this demo, we'll store the keys as serialized PEM files
    # In a real application, you would use proper key serialization and protection
    from cryptography.hazmat.primitives import serialization
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys to files
    with open(os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem'), 'wb') as f:
        f.write(private_pem)
        
    with open(os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem'), 'wb') as f:
        f.write(public_pem)
    
    return private_key, public_key

def get_asymmetric_keys():
    private_key_path = os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem')
    public_key_path = os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem')
    
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        from cryptography.hazmat.primitives import serialization
        
        with open(private_key_path, 'rb') as f:
            private_pem = f.read()
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )
        
        with open(public_key_path, 'rb') as f:
            public_pem = f.read()
            public_key = serialization.load_pem_public_key(public_pem)
            
        return private_key, public_key
    
    return generate_asymmetric_keys()

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
            "admin": ["encrypt", "decrypt", "upload", "download", "generate_keys", "view_files"],
            "editor": ["encrypt", "upload"],
            "viewer": ["download", "view_files"]
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

# Create RBAC system
rbac = RBACSystem()

# ---------- Routes ----------
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if rbac.authenticate(username, password):
            session['user'] = username
            session['role'] = rbac.users[username]['role']
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'
    
    # Pass user credentials for the demo
    users = [
        {"username": "alice", "password": "alice123", "role": "admin"},
        {"username": "bob", "password": "bob123", "role": "viewer"},
        {"username": "charlie", "password": "charlie123", "role": "editor"}
    ]
    
    return render_template('login.html', error=error, users=users)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/encryption')
def encryption():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    # Check if symmetric key exists
    key_exists = os.path.exists(os.path.join(app.config['KEYS_FOLDER'], 'symmetric_key.key'))
    private_key_exists = os.path.exists(os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem'))
    
    # Check user permissions
    can_encrypt = rbac.is_authorized(session['user'], 'encrypt')
    can_decrypt = rbac.is_authorized(session['user'], 'decrypt')
    can_generate_keys = rbac.is_authorized(session['user'], 'generate_keys')
    
    return render_template(
        'encryption.html', 
        key_exists=key_exists,
        private_key_exists=private_key_exists,
        can_encrypt=can_encrypt,
        can_decrypt=can_decrypt,
        can_generate_keys=can_generate_keys,
        username=session['user'],
        role=session['role']
    )

@app.route('/cloud')
def cloud():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Check user permissions
    can_upload = rbac.is_authorized(session['user'], 'upload')
    can_download = rbac.is_authorized(session['user'], 'download')
    can_view_files = rbac.is_authorized(session['user'], 'view_files')
    
    # Get list of files in cloud storage
    files = []
    if os.path.exists(app.config['CLOUD_STORAGE']):
        files = [{
            "name": f,
            "size": os.path.getsize(os.path.join(app.config['CLOUD_STORAGE'], f)),
            "date": time.ctime(os.path.getmtime(os.path.join(app.config['CLOUD_STORAGE'], f)))
        } for f in os.listdir(app.config['CLOUD_STORAGE'])]
    
    return render_template(
        'cloud.html', 
        files=files,
        can_upload=can_upload,
        can_download=can_download,
        can_view_files=can_view_files,
        username=session['user'],
        role=session['role']
    )

@app.route('/visualization')
def visualization():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('visualization.html')

# ---------- API Endpoints ----------
@app.route('/api/generate_keys', methods=['POST'])
def api_generate_keys():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if not rbac.is_authorized(session['user'], 'generate_keys'):
        return jsonify({"error": "Not authorized"}), 403
    
    try:
        symmetric_key = generate_symmetric_key()
        private_key, public_key = generate_asymmetric_keys()
        
        return jsonify({
            "success": True,
            "message": "Keys generated successfully"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/encrypt_text', methods=['POST'])
def api_encrypt_text():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if not rbac.is_authorized(session['user'], 'encrypt'):
        return jsonify({"error": "Not authorized"}), 403
    
    try:
        data = request.json
        plaintext = data.get('plaintext', '')
        
        if not plaintext:
            return jsonify({"error": "No text provided"}), 400
        
        # Get symmetric key
        key = get_symmetric_key()
        
        # Encrypt
        encrypted = symmetric_encrypt(key, plaintext)
        
        # Return as base64 for JSON compatibility
        return jsonify({
            "success": True,
            "encrypted": b64.b64encode(encrypted).decode()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt_text', methods=['POST'])
def api_decrypt_text():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if not rbac.is_authorized(session['user'], 'decrypt'):
        return jsonify({"error": "Not authorized"}), 403
    
    try:
        data = request.json
        encrypted_text = data.get('encrypted', '')
        
        if not encrypted_text:
            return jsonify({"error": "No encrypted text provided"}), 400
        
        # Get symmetric key
        key = get_symmetric_key()
        
        # Decode base64 and decrypt
        encrypted_bytes = b64.b64decode(encrypted_text)
        decrypted = symmetric_decrypt(key, encrypted_bytes)
        
        return jsonify({
            "success": True,
            "decrypted": decrypted if isinstance(decrypted, str) else str(decrypted)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload_file', methods=['POST'])
def api_upload_file():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if not rbac.is_authorized(session['user'], 'upload'):
        return jsonify({"error": "Not authorized"}), 403
    
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    try:
        # Read file data
        file_data = file.read()
        
        # Get symmetric key
        key = get_symmetric_key()
        
        # Encrypt the file
        encrypted_data = symmetric_encrypt(key, file_data)
        
        # Save to cloud storage
        cloud_filename = f"{secure_filename(file.filename)}.encrypted"
        with open(os.path.join(app.config['CLOUD_STORAGE'], cloud_filename), 'wb') as f:
            f.write(encrypted_data)
        
        return jsonify({
            "success": True,
            "message": f"File encrypted and uploaded as {cloud_filename}",
            "filename": cloud_filename
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/download_file/<filename>', methods=['GET'])
def api_download_file(filename):
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if not rbac.is_authorized(session['user'], 'download'):
        return jsonify({"error": "Not authorized"}), 403
    
    try:
        file_path = os.path.join(app.config['CLOUD_STORAGE'], filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        
        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Get symmetric key
        key = get_symmetric_key()
        
        # Decrypt the file
        decrypted_data = symmetric_decrypt(key, encrypted_data)
        
        # Prepare decrypted file for download
        decrypted_filename = filename.replace('.encrypted', '')
        decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        
        with open(decrypted_file_path, 'wb') as f:
            if isinstance(decrypted_data, str):
                f.write(decrypted_data.encode())
            else:
                f.write(decrypted_data)
        
        return send_file(
            decrypted_file_path,
            as_attachment=True,
            download_name=decrypted_filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/list_files', methods=['GET'])
def api_list_files():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if not rbac.is_authorized(session['user'], 'view_files'):
        return jsonify({"error": "Not authorized"}), 403
    
    files = []
    if os.path.exists(app.config['CLOUD_STORAGE']):
        files = [{
            "name": f,
            "size": os.path.getsize(os.path.join(app.config['CLOUD_STORAGE'], f)),
            "date": time.ctime(os.path.getmtime(os.path.join(app.config['CLOUD_STORAGE'], f)))
        } for f in os.listdir(app.config['CLOUD_STORAGE'])]
    
    return jsonify({"files": files})

@app.route('/api/get_key_info', methods=['GET'])
def api_get_key_info():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    symmetric_key_path = os.path.join(app.config['KEYS_FOLDER'], 'symmetric_key.key')
    private_key_path = os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem')
    public_key_path = os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem')
    
    symmetric_key_exists = os.path.exists(symmetric_key_path)
    private_key_exists = os.path.exists(private_key_path)
    public_key_exists = os.path.exists(public_key_path)
    
    # For demo purposes, return a portion of the keys
    symmetric_key_preview = None
    if symmetric_key_exists:
        with open(symmetric_key_path, 'rb') as f:
            key_data = f.read()
            symmetric_key_preview = b64.b64encode(key_data).decode()[:20] + '...'  # Just show the first part for security
    
    return jsonify({
        "symmetric_key_exists": symmetric_key_exists,
        "symmetric_key_preview": symmetric_key_preview,
        "asymmetric_keys_exist": private_key_exists and public_key_exists,
        "created": time.ctime(os.path.getmtime(symmetric_key_path)) if symmetric_key_exists else None
    })

if __name__ == '__main__':
    app.run(debug=True)