# EnigmaPy

EnigmaPy is a simple yet secure file encryption and decryption tool written in Python. It uses AES-GCM for encryption, providing both confidentiality and integrity for your files.

## Features

- Strong encryption using AES-256 in GCM mode
- Secure key derivation using PBKDF2
- Command-line interface for easy integration into scripts
- Confirmation prompts to prevent accidental operations
- Creates new files for encrypted/decrypted content, preserving originals

## Requirements

- Python 3.6 or higher
- cryptography library

## Installation

1. Clone this repository:
   git clone https://github.com/JansonErikson/enigmapy.git
   cd enigmapy

2. Install the required library:
   pip install cryptography

## Usage

The basic syntax for using EnigmaPy is:

python enigmapy.py [encrypt/decrypt] [file_path] [password]

### Encrypting a file

To encrypt a file:

python enigmapy.py encrypt /path/to/your/file your_password

This will create a new file with the `.encrypted` extension.

### Decrypting a file

To decrypt a file:

python enigmapy.py decrypt /path/to/your/file.encrypted your_password

This will create a new file with the `.decrypted` extension.

## Security Notes

- Always use strong, unique passwords for each file you encrypt.
- Keep your passwords safe. If you lose the password, you won't be able to decrypt your file.
- This tool is designed for personal use. For enterprise-level security, consider professional solutions.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is, without any warranty. Always keep backups of your important files.
