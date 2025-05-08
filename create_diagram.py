import matplotlib.pyplot as plt
import os

# Create directory if it doesn't exist
if not os.path.exists('static/images'):
    os.makedirs('static/images')

# Create the diagram
fig, ax = plt.subplots(figsize=(10, 6))
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

# Save the diagram
plt.savefig('cloud-service-encryption/static/images/encryption_diagram.png', dpi=300, bbox_inches='tight')
print("Encryption diagram created successfully!")