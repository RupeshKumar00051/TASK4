#Company : CODTECH IT SOLUTIONS
#NAME : RUPESH KUMAR
#INTERN ID : CT04DA417
#Domain : Cyber Security & Ethical Hacking 
#Duration : 4 weeks
Mentor: Neela Santosh

# TASK4
# Advanced File Encryption Tool

A secure file encryption tool using AES-256 with both command-line and graphical interfaces.

## Features

- **Strong Encryption**: Uses AES-256-CBC with PBKDF2 key derivation
- **Integrity Protection**: HMAC-SHA256 for tamper detection
- **Two Interfaces**: CLI for scripting and GUI for ease of use
- **Directory Support**: Encrypt/decrypt entire directory trees
- **Secure Design**: Proper salting, IV generation, and key stretching

## Installation

```bash
git clone https://github.com/yourusername/file-encryption-tool.git
cd file-encryption-tool
pip install -r requirements.txt
python setup.py install
