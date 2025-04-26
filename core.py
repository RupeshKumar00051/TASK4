import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import json

class FileEncryptor:
    def __init__(self):
        self.SALT_LENGTH = 16
        self.KEY_LENGTH = 32  # AES-256
        self.ITERATIONS = 100000
        self.HMAC_LENGTH = 32

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        return PBKDF2(
            password.encode(),
            salt,
            dkLen=self.KEY_LENGTH,
            count=self.ITERATIONS,
            prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest()
        )

    def _generate_metadata(self) -> dict:
        """Generate encryption metadata"""
        return {
            "version": "1.0",
            "algorithm": "AES-256-CBC",
            "key_derivation": "PBKDF2-HMAC-SHA256",
            "iterations": self.ITERATIONS,
            "salt": os.urandom(self.SALT_LENGTH).hex(),
            "hmac": "SHA256"
        }

    def encrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        """Encrypt a file with AES-256-CBC"""
        try:
            # Generate random salt and IV
            salt = os.urandom(self.SALT_LENGTH)
            iv = get_random_bytes(AES.block_size)
            
            # Derive key from password
            key = self._derive_key(password, salt)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Read input file
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            
            # Pad and encrypt data
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            
            # Generate HMAC for integrity check
            hmac_digest = hmac.new(
                key, 
                iv + ciphertext, 
                hashlib.sha256
            ).digest()
            
            # Prepare metadata
            metadata = self._generate_metadata()
            metadata['iv'] = iv.hex()
            
            # Write output file
            with open(output_path, 'wb') as f:
                f.write(json.dumps(metadata).encode() + b'\n')
                f.write(hmac_digest)
                f.write(ciphertext)
            
            return True
        except Exception as e:
            print(f"Encryption failed: {str(e)}")
            return False

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        """Decrypt a file encrypted with AES-256-CBC"""
        try:
            with open(input_path, 'rb') as f:
                # Read metadata (first line)
                metadata_line = f.readline()
                metadata = json.loads(metadata_line.decode())
                
                # Read HMAC and ciphertext
                hmac_digest = f.read(self.HMAC_LENGTH)
                ciphertext = f.read()
                
                # Get parameters from metadata
                salt = bytes.fromhex(metadata['salt'])
                iv = bytes.fromhex(metadata['iv'])
                
                # Derive key
                key = self._derive_key(password, salt)
                
                # Verify HMAC
                expected_hmac = hmac.new(
                    key,
                    iv + ciphertext,
                    hashlib.sha256
                ).digest()
                
                if not hmac.compare_digest(hmac_digest, expected_hmac):
                    raise ValueError("HMAC verification failed - file may be corrupted or tampered with")
                
                # Decrypt data
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                
                # Write decrypted file
                with open(output_path, 'wb') as f_out:
                    f_out.write(plaintext)
                
                return True
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return False

    def encrypt_directory(self, dir_path: str, output_dir: str, password: str) -> bool:
        """Encrypt all files in a directory"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            for root, _, files in os.walk(dir_path):
                for file in files:
                    input_path = os.path.join(root, file)
                    rel_path = os.path.relpath(input_path, dir_path)
                    output_path = os.path.join(output_dir, rel_path + '.enc')
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    if not self.encrypt_file(input_path, output_path, password):
                        return False
            return True
        except Exception as e:
            print(f"Directory encryption failed: {str(e)}")
            return False

    def decrypt_directory(self, dir_path: str, output_dir: str, password: str) -> bool:
        """Decrypt all files in a directory"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            for root, _, files in os.walk(dir_path):
                for file in files:
                    if file.endswith('.enc'):
                        input_path = os.path.join(root, file)
                        rel_path = os.path.relpath(input_path, dir_path)
                        output_path = os.path.join(
                            output_dir, 
                            rel_path[:-4] if rel_path.endswith('.enc') else rel_path
                        )
                        os.makedirs(os.path.dirname(output_path), exist_ok=True)
                        if not self.decrypt_file(input_path, output_path, password):
                            return False
            return True
        except Exception as e:
            print(f"Directory decryption failed: {str(e)}")
            return False