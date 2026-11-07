# decryptors/xor_decryptor.py

import os

def xor_decrypt(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

def is_mostly_printable(data: bytes, threshold=0.90) -> bool:
    printable = sum(32 <= b <= 126 for b in data)
    return (printable / len(data)) >= threshold if data else False

def brute_force_xor(filepath, save_dir="output/decrypted"):
    with open(filepath, "rb") as f:
        raw = f.read()

    os.makedirs(save_dir, exist_ok=True)
    results = []

    for key in range(256):
        decrypted = xor_decrypt(raw, key)
        if is_mostly_printable(decrypted[:1024]):  # cek hanya sebagian
            output_path = os.path.join(save_dir, f"{os.path.basename(filepath)}.xor_{key:02x}.dec.txt")
            with open(output_path, "wb") as out:
                out.write(decrypted)
            results.append((key, output_path))

    return results
