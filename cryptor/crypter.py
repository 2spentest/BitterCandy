
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sys

def encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

def read_shellcode_from_file(file_path):
    with open(file_path, 'rb') as f:
        shellcode = f.read()
    return shellcode

def save_encrypted_data_to_file(file_path, encrypted_data):
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

if len(sys.argv) != 3:
    print("Usage: python encrypt.py <input_file> <output_file>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

# Example usage
key = get_random_bytes(32)  # AES-256 key
iv = get_random_bytes(16)   # AES initialization vector

shellcode = read_shellcode_from_file(input_file)

encrypted_data = encrypt(shellcode, key, iv)

save_encrypted_data_to_file(output_file, encrypted_data)

# Print the results
print("Key:")
print(','.join('0x{:02x}'.format(x) for x in key))
print("IV:")
print(','.join('0x{:02x}'.format(x) for x in iv))
print("Encrypted shellcode saved to:", output_file)
