import os
import base64
import secrets
import time
import json
import hashlib
import base64 as b64
import matplotlib.pyplot as plt

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from werkzeug.utils import secure_filename
from io import BytesIO
from services.registry import FileRegistry


app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['KEYS_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
app.config['CLOUD_STORAGE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloud_storage')
app.config['REGISTRY_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'registry')

# Create required directories if they don't exist
for directory in [app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], app.config['CLOUD_STORAGE'], app.config['REGISTRY_FOLDER']]:
    if not os.path.exists(directory):
        os.makedirs(directory)


#Save metrics
def save_encryption_metrics(metrics):
    metrics_file = os.path.join(app.config['KEYS_FOLDER'], 'encryption_metrics.json')
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f)


#Load metrics
def load_encryption_metrics():
    metrics_file = os.path.join(app.config['KEYS_FOLDER'], 'encryption_metrics.json')
    if os.path.exists(metrics_file):
        with open(metrics_file, 'r') as f:
            import json
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("Error decoding encryption metrics file.  Returning a blank slate.")
                return {
                    'symmetric_encrypt': [],
                    'rsa_encrypt': []
                }
    else:
        json =  {
            'symmetric_encrypt': [],
            'rsa_encrypt': []
        }
        save_encryption_metrics(json)
        return json


# Initialize the file registry
file_registry = FileRegistry(base_dir=os.path.dirname(os.path.abspath(__file__)))

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
    encryption_metrics=load_encryption_metrics()
    start = time.time()
    f = Fernet(key)
    if isinstance(data, str):

        encryption_metrics['symmetric_encrypt'].append(time.time() - start)
        return f.encrypt(data.encode())

    encryption_metrics['symmetric_encrypt'].append(time.time() - start)
    save_encryption_metrics(encryption_metrics)

    return f.encrypt(data)

def symmetric_decrypt(key, ciphertext):
    encryption_metrics=load_encryption_metrics()
    start = time.time()
    f = Fernet(key)
    decrypted = f.decrypt(ciphertext)
    try:
        encryption_metrics['symmetric_decrypt'].append(time.time() - start)
        save_encryption_metrics(encryption_metrics)
        return decrypted.decode()
    except UnicodeDecodeError:
        encryption_metrics['symmetric_decrypt'].append(time.time() - start)
        save_encryption_metrics(encryption_metrics)
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
    encryption_metrics = load_encryption_metrics()
    start = time.time()
    if isinstance(data, str):
        data = data.encode()
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encryption_metrics['rsa_encrypt'].append(time.time() - start)
    save_encryption_metrics(encryption_metrics)
    return encrypted_data

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ---------- RBAC Implementation ----------

class RBACSystem:
    _users = {
        "alice": {"role": "admin", "password": "alice123" },
        "bob": {"role": "viewer", "password": "bob123", "salt": "salt_for_bob"},
        "charlie": {"role": "editor", "password": "charlie123", "salt": "salt_for_charlie"}
    }

    _demo_users = {
        "alice": {"role": "admin", "password": "alice123" },
        "bob": {"role": "viewer", "password": "bob123"},
        "charlie": {"role": "editor", "password": "charlie123"}
    }

    roles_permissions = {
        "admin": ["encrypt", "decrypt", "upload", "download", "generate_keys", "view_files", "share_files"],
        "editor": ["encrypt", "upload", "share_files", "view_files"],
        "viewer": ["download", "view_files"]
    }

    def __init__(self):
        # Pre-hash passwords for the existing users.  In a real system, this would be done at initial user creation.
        for i, (username, user_data) in enumerate(self._demo_users.items()):
            salt = secrets.token_hex(16)
            hashed_password = self._hash_password(user_data["password"], salt)
            user_data["password"] = hashed_password
            user_data["salt"] = salt
            self._users[username] = user_data


    def _hash_password(self, password, salt=None):
        if salt is None:
            salt = secrets.token_hex(16)
        salted_password = salt.encode() + password.encode()
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        return hashed_password

    def add_user(self, username, role, password):
        if username not in self._users:
            salt = secrets.token_hex(16)
            print(password)
            hashed_password = self._hash_password(password, salt)
            self._users[username] = {"role": role, "password": hashed_password, "salt": salt}
            return True
        return False

    @property
    def users(self):
        return self._users

    def authenticate(self, username, password):
        user = self._users.get(username)
        if not user:
            return False
        salt = user.get("salt")
        if not salt:
            return False

        hashed_input = self._hash_password(password, salt)
        print(user["password"])
        print(hashed_input)
        return user["password"] == hashed_input

    def is_authorized(self, username, action):
        user = self._users.get(username)
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'viewer')  # Default role

        # Basic validation
        if not username or not password:
            error = 'Username and password are required.'
        elif username in rbac.users:
            error = 'Username already exists.'
        elif role not in rbac.roles_permissions:
            error = 'Invalid role selected.'
        else:
            # Create new user
            if rbac.add_user(username, role, password):
                return redirect(url_for('login'))
            else:
                error = 'Failed to create user.'

    # For the demo, pass available roles to the signup page
    available_roles = list(rbac.roles_permissions.keys())
    return render_template('signup.html', error=error, roles=available_roles)


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
    can_share_files = rbac.is_authorized(session['user'], 'share_files')

    # Get list of files in cloud storage
    files = []
    if os.path.exists(app.config['CLOUD_STORAGE']):
        # Get files from cloud storage directory
        basic_files = [{
            "name": f,
            "size": os.path.getsize(os.path.join(app.config['CLOUD_STORAGE'], f)),
            "date": time.ctime(os.path.getmtime(os.path.join(app.config['CLOUD_STORAGE'], f)))
        } for f in os.listdir(app.config['CLOUD_STORAGE'])]

        # Enhance files with registry information if available
        files = []
        for file in basic_files:
            # Try to get additional metadata from registry
            reg_id, file_details = file_registry.get_file_by_name(file["name"])
            if file_details:
                file["owner"] = file_details.get("owner", session['user'])
                file["file_id"] = reg_id
            files.append(file)

    # Get shared files for the user
    shared_files = []
    if 'user' in session:
        shared_files = file_registry.list_files_shared_with_user(session['user'])

        # Format dates for shared files and add additional info
        for shared_file in shared_files:
            if "date_shared" in shared_file:
                shared_file["date_shared_formatted"] = time.ctime(shared_file["date_shared"])
            if "owner" not in shared_file:
                shared_file["owner"] = "Unknown"
            if "filename" not in shared_file and "original_filename" in shared_file:
                shared_file["filename"] = shared_file["original_filename"]


    return render_template(
        'cloud.html',
        files=files,
        shared_files=shared_files,
        can_upload=can_upload,
        can_download=can_download,
        can_view_files=can_view_files,
        can_share_files=can_share_files,
        session=session,
    )

@app.route('/api/metrics', methods=['GET'])
def api_metrics():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    # Only viewers or higher
    if not rbac.is_authorized(session['user'], 'view_files'):
        return jsonify({"error": "Not authorized"}), 403
    return jsonify(load_encryption_metrics())

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

        # Generate a filename for storing the encrypted text
        timestamp = int(time.time())
        filename = f"encrypted_text_{timestamp}.txt"
        file_path = os.path.join(app.config['CLOUD_STORAGE'], filename)

        # Save encrypted data to cloud storage
        with open(file_path, 'wb') as f:
            f.write(encrypted)

        # Return as base64 for JSON compatibility
        return jsonify({
            "success": True,
            "encrypted": b64.b64encode(encrypted).decode(),
            "filename": filename,
            "message": f"Encrypted text saved as {filename}"
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

    # Ensure upload directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['CLOUD_STORAGE'], exist_ok=True)

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
        cloud_file_path = os.path.join(app.config['CLOUD_STORAGE'], cloud_filename)

        with open(cloud_file_path, 'wb') as f:
            f.write(encrypted_data)

        # Register the file in the registry with current user as owner
        file_size = len(encrypted_data)
        file_metadata = {
            "size": file_size,
            "original_name": file.filename,
            "encrypted": True,
            "encryption_type": "symmetric",
            "upload_date": time.time()
        }

        # Register file in the registry
        success, file_id = file_registry.register_file(
            cloud_filename,
            session['user'],
            "standard",
            file_metadata
        )

        if not success:
            print(f"Warning: Failed to register file {cloud_filename} in registry: {file_id}")

        return jsonify({
            "success": True,
            "message": f"File encrypted and uploaded as {cloud_filename}",
            "filename": cloud_filename,
            "owner": session['user']
        })
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/download_file/<filename>', methods=['GET'])
def api_download_file(filename):
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if not rbac.is_authorized(session['user'], 'download'):
        return jsonify({"error": "Not authorized"}), 403

    # Ensure directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['CLOUD_STORAGE'], exist_ok=True)

    try:
        file_path = os.path.join(app.config['CLOUD_STORAGE'], filename)

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        # Check file registry to verify access permissions
        owner = file_registry.get_file_owner(filename)
        file_id, file_details = file_registry.get_file_by_name(filename)

        # Only allow download if user is the owner or admin
        if owner and owner != session['user'] and session.get('role') != 'admin':
            # Check if file is shared with the user
            if not (file_details and 'shared_with' in file_details and
                  session['user'] in file_details.get('shared_with', [])):
                return jsonify({"error": "Access denied - you don't have permission to download this file"}), 403

        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        # Get symmetric key
        key = get_symmetric_key()

        # Record download in registry if we have file_id
        if file_id:
            file_registry.update_file_metadata(file_id, {
                "last_downloaded": time.time(),
                "downloaded_by": session['user']
            })

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

    # Check if admin wants to see all files
    show_all = request.args.get('all', 'false').lower() == 'true' and session.get('role') == 'admin'

    files = []
    if os.path.exists(app.config['CLOUD_STORAGE']):
        # Get files from cloud storage
        cloud_files = os.listdir(app.config['CLOUD_STORAGE'])

        for f in cloud_files:
            file_path = os.path.join(app.config['CLOUD_STORAGE'], f)
            if os.path.isfile(file_path):
                # Get file info
                file_size = os.path.getsize(file_path)
                file_date = time.ctime(os.path.getmtime(file_path))

                # Get owner from registry
                owner = file_registry.get_file_owner(f)
                file_id = None

                if not owner:
                    # If not in registry, register it with current user
                    file_path = os.path.join(app.config['CLOUD_STORAGE'], f)
                    success, reg_id = file_registry.register_file(
                        f,
                        session['user'],
                        "standard",
                        {
                            "size": file_size,
                            "date": file_date,
                            "last_accessed": time.time()
                        },
                        file_path
                    )
                    owner = session['user']
                    if success:
                        file_id = reg_id
                else:
                    # If in registry, get the file_id
                    reg_id, file_info = file_registry.get_file_by_name(f)
                    if reg_id:
                        file_id = reg_id

                # Only include if admin viewing all or user owns file
                if show_all or owner == session['user']:
                    files.append({
                        "name": f,
                        "size": file_size,
                        "date": file_date,
                        "owner": owner,
                        "type": "standard",
                        "shareable": True,
                        "file_id": file_id
                    })

    # Get shared files
    shared_files = []
    try:
        if show_all:
            # If admin, get all files from registry
            all_files = file_registry.list_all_files()
            for file in all_files:
                if (file.get("type") == "shared" and
                    file.get("filename") not in [f["name"] for f in files]):
                    # Calculate sharing info
                    share_count = len(file.get("shared_with", []))

                    shared_files.append({
                        "file_id": file.get("file_id"),
                        "original_filename": file.get("filename", "Unknown"),
                        "size": file.get("metadata", {}).get("size", 0),
                        "owner": file.get("owner", "Unknown"),
                        "date_created": file.get("created"),
                        "date_shared": file.get("metadata", {}).get("upload_date"),
                        "type": "shared",
                        "shared_with": file.get("shared_with", []),
                        "share_count": share_count,
                        "is_owner": file.get("owner") == session['user']
                    })
        else:
            # Get user's shared files (files shared with the user)
            user_shared = file_registry.list_files_shared_with_user(session['user'])
            for shared_file in user_shared:
                if shared_file not in shared_files:  # Avoid duplicates
                    shared_files.append(shared_file)

            # Also get files owned by user that are shared with others
            user_files = file_registry.list_files_by_owner(session['user'])
            for file in user_files:
                # Only include files that are shared with others and not already in the list
                if (len(file.get("shared_with", [])) > 0 and
                    file.get("filename") not in [f["name"] for f in files] and
                    file.get("file_id") not in [f.get("file_id") for f in shared_files]):

                    shared_files.append({
                        "file_id": file.get("file_id"),
                        "original_filename": file.get("filename", "Unknown"),
                        "size": file.get("metadata", {}).get("size", 0),
                        "owner": session['user'],
                        "is_owner": True,
                        "date_created": file.get("created"),
                        "date_shared": file.get("metadata", {}).get("upload_date"),
                        "type": "shared",
                        "shared_with": file.get("shared_with", []),
                        "share_count": len(file.get("shared_with", []))
                    })
    except Exception as e:
        print(f"Error getting shared files: {str(e)}")

    # Combine files and shared files
    all_files = files + shared_files

    return jsonify({
        "files": files,
        "shared_files": shared_files,
        "all_files": all_files
    })

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

@app.route('/api/share_file', methods=['POST'])
def api_share_file():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if not rbac.is_authorized(session['user'], 'share_files'):
        return jsonify({"error": "Not authorized"}), 403

    try:
        data = request.json
        file_id = data.get('file_id')
        recipients = data.get('recipients', [])

        if not file_id:
            return jsonify({"error": "No file ID provided"}), 400

        if not recipients:
            return jsonify({"error": "No recipients provided"}), 400

        # First check if this is a regular filename or a registry file ID
        if '.' in file_id:  # Likely a filename
            # Look up the file ID from registry
            reg_id, file_details = file_registry.get_file_by_name(file_id)
            if reg_id:
                file_id = reg_id

        # Get file details from registry
        file_details = file_registry.get_file_by_id(file_id)

        if not file_details:
            # Try once more with the original file_id (might be a filename)
            # This is needed if get_file_by_name failed above
            success, result = file_registry.register_file(
                file_id,  # Use as filename
                session['user'],
                "standard",
                {
                    "shared": True,
                    "date_shared": time.time()
                }
            )
            if success:
                file_id = result  # Use the new file_id
                file_details = file_registry.get_file_by_id(file_id)
            else:
                return jsonify({"error": "File not found in registry"}), 404

        # Check if user is the owner or admin
        owner = file_details.get("owner", session['user'])
        if owner != session['user'] and session['role'] != 'admin':
            return jsonify({"error": "You don't have permission to share this file"}), 403

        success_count = 0
        errors = []

        for recipient in recipients:
            # Don't share with yourself
            if recipient == owner:
                errors.append(f"Cannot share with yourself: {recipient}")
                continue

            # Check if recipient exists in users list
            if recipient not in rbac.users:
                errors.append(f"User does not exist: {recipient}")
                continue

            # Check recipient's role and permissions
            recipient_role = rbac.users[recipient]["role"]

            # Only admin and viewer roles can access shared files by default
            # (since they have the download permission)
            if recipient_role not in ["admin", "viewer", "editor"] and rbac.is_authorized(recipient, "download"):
                errors.append(f"User {recipient} doesn't have permission to access shared files.")
                continue

            # Share using registry
            share_success, message = file_registry.share_file(file_id, recipient)

            if share_success:
                success_count += 1
            else:
                errors.append(f"Failed to share with {recipient}: {message}")

        return jsonify({
            "success": success_count > 0,
            "message": f"File shared with {success_count} users",
            "errors": errors
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/shared_files', methods=['GET'])
def api_shared_files():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if not rbac.is_authorized(session['user'], 'view_files'):
        return jsonify({"error": "Not authorized"}), 403

    try:
        # Get files shared with the current user from registry
        shared_files = file_registry.list_files_shared_with_user(session['user'])

        # Process the shared files to ensure all required fields are present
        processed_files = []
        for sf in shared_files:
            # Add type if missing
            if "type" not in sf:
                sf["type"] = "shared"
            # Add date_shared if missing
            if "date_shared" not in sf:
                sf["date_shared"] = time.time()
            # Add share count
            sf["share_count"] = len(sf.get("shared_with", []))

            # Format the date for display
            if "date_shared" in sf:
                sf["date_shared_formatted"] = time.ctime(sf["date_shared"])

            # Ensure filename is available
            if "filename" not in sf:
                sf["filename"] = sf.get("original_filename", "Unknown")

            # Check if current user is the owner
            sf["is_owner"] = sf.get("owner") == session['user']

            processed_files.append(sf)

        return jsonify({"shared_files": processed_files})
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve shared files: {str(e)}"}), 500

@app.route('/api/list_users', methods=['GET'])
def api_list_users():
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if not rbac.is_authorized(session['user'], 'share_files'):
        return jsonify({"error": "Not authorized"}), 403

    try:
        users = list(rbac.users.keys())
        return jsonify({"users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/download_shared_file/<file_id>', methods=['GET'])
def api_download_shared_file(file_id):
    if 'user' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if not rbac.is_authorized(session['user'], 'download'):
        return jsonify({"error": "Not authorized"}), 403

    # Ensure directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    try:
        # Get the file details from registry
        file_details = file_registry.get_file_by_id(file_id)

        if not file_details:
            return jsonify({"error": "File not found in registry"}), 404

        # Check if user has access to this file
        if not (file_details.get("owner") == session['user'] or
                session['user'] in file_details.get("shared_with", []) or
                session.get('role') == 'admin'):
            return jsonify({"error": "Access denied - you don't have permission to download this file"}), 403

        # Get the file path
        filename = file_details.get("filename")
        file_path = os.path.join(app.config['CLOUD_STORAGE'], filename)

        if not os.path.exists(file_path):
            return jsonify({"error": f"File data not found on server: {filename}"}), 404

        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        # Record download in registry
        file_registry.update_file_metadata(file_id, {
            "last_downloaded": time.time(),
            "downloaded_by": session['user']
        })

        # For now, just return the encrypted file
        # In a real application, this would use shared keys to decrypt
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        with open(temp_path, 'wb') as f:
            f.write(encrypted_data)

        # Get original filename
        original_filename = file_details.get("metadata", {}).get("original_name", filename)

        return send_file(
            temp_path,
            as_attachment=True,
            download_name=original_filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Scan existing directories to populate registry
    try:
        print("Scanning and registering existing files...")
        # Scan cloud storage directory
        if os.path.exists(app.config['CLOUD_STORAGE']):
            success, result = file_registry.scan_directory_and_register(
                app.config['CLOUD_STORAGE'],
                "system",
                "standard"
            )
            if success:
                print(f"Cloud storage scan: {result['success_count']} files registered")
    except Exception as e:
        print(f"Error during startup file registration: {str(e)}")

    app.run(debug=True)
