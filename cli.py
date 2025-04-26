import argparse
from encryption_tool.core import FileEncryptor
import getpass
import sys

def main():
    parser = argparse.ArgumentParser(
        description="Advanced File Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  encrypt-tool encrypt file.txt file.enc
  encrypt-tool decrypt file.enc file.txt --password "mypassword"
  encrypt-tool encrypt-dir mydocs/ encrypted/ --ask-password
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt file command
    enc_file = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_file.add_argument("input", help="Input file path")
    enc_file.add_argument("output", help="Output file path")
    enc_file.add_argument("-p", "--password", help="Encryption password")
    enc_file.add_argument("--ask-password", action="store_true",
                        help="Prompt for password securely")

    # Decrypt file command
    dec_file = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_file.add_argument("input", help="Input file path")
    dec_file.add_argument("output", help="Output file path")
    dec_file.add_argument("-p", "--password", help="Decryption password")
    dec_file.add_argument("--ask-password", action="store_true",
                        help="Prompt for password securely")

    # Encrypt directory command
    enc_dir = subparsers.add_parser("encrypt-dir", help="Encrypt a directory")
    enc_dir.add_argument("input", help="Input directory path")
    enc_dir.add_argument("output", help="Output directory path")
    enc_dir.add_argument("-p", "--password", help="Encryption password")
    enc_dir.add_argument("--ask-password", action="store_true",
                        help="Prompt for password securely")

    # Decrypt directory command
    dec_dir = subparsers.add_parser("decrypt-dir", help="Decrypt a directory")
    dec_dir.add_argument("input", help="Input directory path")
    dec_dir.add_argument("output", help="Output directory path")
    dec_dir.add_argument("-p", "--password", help="Decryption password")
    dec_dir.add_argument("--ask-password", action="store_true",
                        help="Prompt for password securely")

    args = parser.parse_args()

    # Get password
    password = args.password
    if args.ask_password or not password:
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty", file=sys.stderr)
            sys.exit(1)

    encryptor = FileEncryptor()
    success = False

    if args.command == "encrypt":
        success = encryptor.encrypt_file(args.input, args.output, password)
    elif args.command == "decrypt":
        success = encryptor.decrypt_file(args.input, args.output, password)
    elif args.command == "encrypt-dir":
        success = encryptor.encrypt_directory(args.input, args.output, password)
    elif args.command == "decrypt-dir":
        success = encryptor.decrypt_directory(args.input, args.output, password)

    if success:
        print("Operation completed successfully")
        sys.exit(0)
    else:
        print("Operation failed", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()