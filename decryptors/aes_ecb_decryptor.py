# decryptors/aes_ecb_decryptor.py

import os
from Crypto.Cipher import AES

def try_decrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def is_mostly_printable(data: bytes, threshold=0.90) -> bool:
    printable = sum(32 <= b <= 126 for b in data)
    return (printable / len(data)) >= threshold if data else False

def brute_force_aes_ecb(filepath, save_dir="output/decrypted"):
    with open(filepath, "rb") as f:
        raw = f.read()

    os.makedirs(save_dir, exist_ok=True)
    results = []

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
            decrypted = try_decrypt_aes_ecb(raw[:len(raw)//16*16], key)  # block align
            if is_mostly_printable(decrypted[:1024]):
                out_path = os.path.join(save_dir, f"{os.path.basename(filepath)}.aes_ecb_{key.decode('latin1')}.dec.txt")
                with open(out_path, "wb") as out:
                    out.write(decrypted)
                results.append((key.decode('latin1'), out_path))
        except Exception:
            continue

    return results
