from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------- Symmetric Encryption Layer ----------

def generate_symmetric_key():
    # Generate a Fernet key (AES-based)
    return Fernet.generate_key()

def symmetric_encrypt(key, plaintext):
    f = Fernet(key)
    return f.encrypt(plaintext.encode())

def symmetric_decrypt(key, ciphertext):
    f = Fernet(key)
    return f.decrypt(ciphertext).decode()

# ---------- Asymmetric Encryption for Key Exchange ----------

def generate_asymmetric_keys():
    # Generate RSA private and public keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    # Encrypt data using RSA public key
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, ciphertext):
    # Decrypt data using RSA private key
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ---------- Demonstration: Encrypting a Data File ----------

def encrypt_data_file(filename, symmetric_key):
    with open(filename, 'rb') as file:
        data = file.read()
    encrypted_data = symmetric_encrypt(symmetric_key, data.decode())
    # Store the encrypted data (in practice, upload to cloud storage)
    with open(filename + ".enc", 'wb') as file:
        file.write(encrypted_data)
    print(f"File {filename} encrypted and stored as {filename}.enc")

def decrypt_data_file(filename, symmetric_key):
    with open(filename, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = symmetric_decrypt(symmetric_key, encrypted_data)
    print("Decrypted data: ", decrypted_data)
    return decrypted_data

# Example usage:
if __name__ == "__main__":
    # Generate keys
    sym_key = generate_symmetric_key()
    private_rsa, public_rsa = generate_asymmetric_keys()
    
    # Encrypt the symmetric key with RSA public key for secure sharing
    encrypted_sym_key = rsa_encrypt(public_rsa, sym_key)
    
    # Later, an authorized user with the RSA private key can decrypt the symmetric key
    decrypted_sym_key = rsa_decrypt(private_rsa, encrypted_sym_key)
    assert decrypted_sym_key == sym_key
    
    # Encrypt a file (simulate with a simple text file)
    sample_filename = "sample_data.txt"  # Ensure this file exists
    encrypt_data_file(sample_filename, sym_key)
    
    # Decrypt the file (only authorized users can do this)
    decrypted_text = decrypt_data_file(sample_filename + ".enc", sym_key)
