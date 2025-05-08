# Cloud Service Encryption Demo

This project demonstrates how cloud service encryption works through a web interface. It showcases various security features including symmetric/asymmetric encryption, role-based access control, and secure file storage.

## Features

- **User Authentication**: Login with different roles (admin, editor, viewer)
- **Role-Based Access Control**: Different permissions based on user roles
- **Encryption**: Text and file encryption/decryption using symmetric keys
- **Key Management**: Generate and manage encryption keys
- **Secure File Storage**: Upload, store, and download encrypted files
- **Visualization**: Visual explanation of the encryption process

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone the repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

To start the application, run:

```bash
python app.py
```

This will start a Flask development server, and you can access the application by navigating to `http://127.0.0.1:5000` in your web browser.

## Demo Users

For demonstration purposes, the following users are available:

- **Admin User**:
  - Username: `alice`
  - Password: `alice123`
  - Permissions: encrypt, decrypt, upload, download, generate keys

- **Viewer User**:
  - Username: `bob`
  - Password: `bob123`
  - Permissions: download

- **Editor User**:
  - Username: `charlie`
  - Password: `charlie123`
  - Permissions: encrypt, upload

## Project Structure

- `app.py`: Main Flask application
- `static/`: Static files (CSS, JavaScript, images)
- `templates/`: HTML templates
- `cloud_storage/`: Simulated cloud storage directory
- `keys/`: Directory for storing encryption keys
- `uploads/`: Temporary directory for decrypted downloads

## Notes

This is a demonstration application only and should not be used in production without proper security enhancements and code review.