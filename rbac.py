# A simple in-memory RBAC implementation

# Define roles and their permissions
ROLES_PERMISSIONS = {
    "admin": ["encrypt", "decrypt", "upload", "download"],
    "editor": ["encrypt", "upload"],
    "viewer": ["download"]
}

# Sample user data
USERS = {
    "alice": {"role": "admin"},
    "bob": {"role": "viewer"},
    "charlie": {"role": "editor"}
}

def is_authorized(username, action):
    user = USERS.get(username)
    if not user:
        return False
    role = user["role"]
    return action in ROLES_PERMISSIONS.get(role, [])

# Example usage for access control:
def access_data(username, action, symmetric_key, filename):
    if is_authorized(username, action):
        if action == "download":
            return decrypt_data_file(filename + ".enc", symmetric_key)
        elif action == "upload":
            # Code for uploading data would go here.
            print(f"{username} is authorized to upload data.")
        else:
            print(f"Action {action} performed by {username}")
    else:
        print(f"User {username} is not authorized to perform {action}")

# Demonstrate access control
if __name__ == "__main__":
    # Assume keys and file operations have been performed as earlier.
    user = "alice"
    action = "download"
    access_data(user, action, sym_key, sample_filename)
