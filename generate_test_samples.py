# generate_test_samples.py

import os
from Crypto.Cipher import AES

def pad(text, block_size=16):
    pad_len = block_size - (len(text) % block_size)
    return text + bytes([pad_len] * pad_len)

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data)
    return cipher.encrypt(padded)

def main():
    os.makedirs("test_samples", exist_ok=True)
    plain = b"Ini adalah data rahasia untuk uji coba Kryptolens.\n"

    # XOR sample
    xor_key = b"testxor"
    xor_encrypted = xor_encrypt(plain, xor_key)
    with open("test_samples/xor_test.enc", "wb") as f:
        f.write(xor_encrypted)
    print("✅ XOR sample created: xor_test.enc (key: testxor)")

    # AES ECB samples
    candidate_keys = [
        b'0000000000000000',
        b'1234567890abcdef',
        b'password12345678',
        b'aaaaaaaaaaaaaaaa',
        b'qwertyuiopasdfgh',
        b'letmein123456789'
    ]

    for key in candidate_keys:
        try:
            enc = aes_ecb_encrypt(plain, key)
            fname = f"test_samples/aes_test_{key.decode('latin1')}.enc"
            with open(fname, "wb") as f:
                f.write(enc)
            print(f"✅ AES sample created: {os.path.basename(fname)} (key: {key.decode('latin1')})")
        except Exception as e:
            print(f"❌ Error creating AES with key: {key} → {e}")

if __name__ == "__main__":
    main()
