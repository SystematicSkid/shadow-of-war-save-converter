import sys
import struct
import re
from argparse import ArgumentParser
from pathlib import Path
from Crypto.Cipher import AES
from typing import Tuple, Union, BinaryIO, Optional

class SaveFileProcessor:
    CIPHER_MODE = AES.MODE_CBC
    RAW_KEY = "ad@210766@vac94Cd_?dVt5$alivjz$e"
    RAW_IV = "yuwgb@oftv@gx$t3"
    MAGIC = "SOM3"
    HEADER_FORMAT = '<4s4s4s4s'
    HEADER_SIZE = 16
    FILENAME_KEY_PATTERN = r'^([0-9a-fA-F]{8})_ShadowOfWar\.sav$'

    def __init__(self, input_file: Path):
        self.input_file = input_file
        self.iv = bytes(self.RAW_IV, 'utf-8')

    @classmethod
    def infer_key_from_filename(cls, filename: str) -> Optional[int]:
        """Try to extract the decrypt key from the filename."""
        match = re.match(cls.FILENAME_KEY_PATTERN, filename)
        if match:
            key_hex = match.group(1)
            return int(key_hex, 16)
        return None

    @staticmethod
    def parse_key_value(value: str) -> int:
        """Parse hex or decimal input into integer."""
        try:
            if value.startswith("0x"):
                return int(value, 16)
            return int(value)
        except ValueError:
            raise ValueError(f"Invalid key value: {value}. Must be decimal or hexadecimal (0x...)")

    def construct_key(self, set_data: bytes, key_value: int) -> bytes:
        """Construct encryption/decryption key."""
        new_key = bytearray(self.RAW_KEY.encode())
        
        # Set data mapping
        key_positions = [(11, 1), (26, 0), (17, 3), (18, 2)]
        for pos, idx in key_positions:
            new_key[pos] = set_data[idx]
        
        # Map steamid/key bytes
        version_bytes = [
            (key_value >> shift) & 0xFF
            for shift in (24, 16, 8, 0)
        ]
        key_mapping = [(30, 2), (10, 3), (2, 0), (22, 1)]
        for pos, idx in key_mapping:
            new_key[pos] = version_bytes[idx]
        
        return bytes(new_key)

    def process_file(self, decrypt_key: int, encrypt_key: int, dump: bool) -> None:
        """Process the save file with given decrypt and encrypt keys."""
        try:
            data = self.read_save_file()
            header, encrypted_data = data[:self.HEADER_SIZE], data[self.HEADER_SIZE:]
            
            # Decrypt
            decrypted_data, key_data = self.decrypt_data(encrypted_data, header, decrypt_key)
            if dump:
                self.write_decrypted_data(decrypted_data)
            
            # Encrypt
            encrypted_data = self.encrypt_data(decrypted_data, key_data, encrypt_key)
            self.write_encrypted_data(encrypted_data, header, encrypt_key)
            
            print("File processing completed successfully!")
            
        except Exception as e:
            print(f"Error processing file: {e}")
            sys.exit(1)

    def read_save_file(self) -> bytes:
        """Read and return save file contents."""
        try:
            with open(self.input_file, 'rb') as file:
                return file.read()
        except IOError as e:
            raise IOError(f"Failed to read input file: {e}")

    def decrypt_data(self, data: bytes, header: bytes, key_value: int) -> Tuple[bytes, bytes]:
        """Decrypt save file data."""
        magic, key_data, _, _ = struct.unpack(self.HEADER_FORMAT, header)
        
        if magic != bytes(self.MAGIC, 'utf-8'):
            raise ValueError("Invalid magic number in file header")
            
        key = self.construct_key(key_data, key_value)
        cipher = AES.new(key, self.CIPHER_MODE, self.iv)
        return cipher.decrypt(data), key_data

    def encrypt_data(self, data: bytes, key_data: bytes, key_value: int) -> bytes:
        """Encrypt save file data."""
        key = self.construct_key(key_data, key_value)
        cipher = AES.new(key, self.CIPHER_MODE, self.iv)
        return cipher.encrypt(data)

    def write_decrypted_data(self, data: bytes) -> None:
        """Write decrypted data to file."""
        output_path = self.input_file.with_name("decrypted_save.sav")
        self._write_file(output_path, data)

    def write_encrypted_data(self, data: bytes, header: bytes, key_value: int) -> None:
        """Write encrypted data with header to file."""
        magic, key_data, file_len, decrypted_len = struct.unpack(self.HEADER_FORMAT, header)
        new_header = struct.pack(self.HEADER_FORMAT, magic, key_data, file_len, decrypted_len)
        
        # Create filename with hex key value
        output_name = f"{hex(key_value)[2:].zfill(8)}_ShadowOfWar.sav"
        output_path = self.input_file.parent / output_name
        
        self._write_file(output_path, new_header + data)

    @staticmethod
    def _write_file(path: Path, data: bytes) -> None:
        """Helper method to write data to file."""
        try:
            with open(path, 'wb') as file:
                file.write(data)
        except IOError as e:
            raise IOError(f"Failed to write to {path}: {e}")

def main():
    parser = ArgumentParser(description="Save file decryptor/encryptor")
    parser.add_argument("filename", help="Input save file path")
    parser.add_argument("--original-id", 
                      help="The steam ID of the original file. Must be Steam3 format."
                            "Decryption key (decimal or hex with 0x prefix). "
                           "If not provided, will attempt to infer from filename.")
    parser.add_argument("--new-id", required=True,
                      help="The steam ID of the new file. Must be Steam3 format."
                            "If converting to GOG, use 0x0."
                      )
    parser.add_argument("--dump",
                        help="Dump decrypted data to file for debugging", default=False)
    
    args = parser.parse_args()
    
    # Parse input file path
    input_path = Path(args.filename)
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' does not exist")
        sys.exit(1)
    print("Args: ", args)
    # Initialize processor
    processor = SaveFileProcessor(input_path)
    
    # Parse encrypt key
    try:
        encrypt_key = processor.parse_key_value(args.new_id)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Get decrypt key from argument or filename
    decrypt_key = None
    if args.original_id:
        try:
            decrypt_key = processor.parse_key_value(args.original_id)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        decrypt_key = processor.infer_key_from_filename(input_path.name)
        if decrypt_key is None:
            print("Error: Could not infer Steam ID from filename and --original not provided")
            print("Filename must be in format: xxxxxxxx_ShadowOfWar.sav where xxxxxxxx is the hex key")
            sys.exit(1)
        print(f"Inferred decrypt key from filename: 0x{decrypt_key:08x}")
    
    processor.process_file(decrypt_key, encrypt_key, args.dump)

if __name__ == '__main__':
    main()