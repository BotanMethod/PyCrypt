import hashlib
import argparse

def generate_key(password: str) -> tuple[bytes, bytes]:
    """Generation of XOR and shift keys from password"""
    key = hashlib.sha256(password.encode()).digest()
    return key[:16], key[16:]  # XOR key (16 bytes), Shift key (16 bytes)

def encrypt_byte(byte: int, xor_key: bytes, shift_key: bytes, index: int) -> int:
    """Encryption of a single byte"""
    xor_byte = xor_key[index % len(xor_key)]
    encrypted = byte ^ xor_byte
    
    shift = shift_key[index % len(shift_key)] % 7 + 1  # Shift from 1 to 7 bits
    encrypted = ((encrypted << shift) | (encrypted >> (8 - shift))) & 0xFF
    return encrypted

def decrypt_byte(encrypted_byte: int, xor_key: bytes, shift_key: bytes, index: int) -> int:
    """Decryption of a single byte"""
    shift = shift_key[index % len(shift_key)] % 7 + 1
    
    # Reverse shift
    decrypted = ((encrypted_byte >> shift) | (encrypted_byte << (8 - shift))) & 0xFF
    
    xor_byte = xor_key[index % len(xor_key)]
    return decrypted ^ xor_byte

def process_file(input_path: str, output_path: str, password: str, mode: str):
    """File processing"""
    xor_key, shift_key = generate_key(password)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        index = 0
        while True:
            chunk = f_in.read(1024)  # Reading in 1KB blocks
            if not chunk:
                break
            
            processed = []
            for byte in chunk:
                if mode == 'encrypt':
                    new_byte = encrypt_byte(byte, xor_key, shift_key, index)
                else:
                    new_byte = decrypt_byte(byte, xor_key, shift_key, index)
                
                processed.append(new_byte)
                index += 1
            
            f_out.write(bytes(processed))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypter/Decryptor of files")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Mode')
    parser.add_argument('input', help='File for encrypt/File for decrypt')
    parser.add_argument('output', help="Output file (Where data will save)")
    parser.add_argument('password', help='Encrypt/Decrypt password')
    
    args = parser.parse_args()
    
    process_file(
        args.input,
        args.output,
        args.password,
        args.mode
    )