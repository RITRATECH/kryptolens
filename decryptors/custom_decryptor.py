# decryptors/custom_decryptor.py

import os
from Crypto.Cipher import AES

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data[:len(data)//16*16])  # blok rata

def is_mostly_printable(data: bytes, threshold=0.90) -> bool:
    printable = sum(32 <= b <= 126 for b in data)
    return (printable / len(data)) >= threshold if data else False

def custom_decrypt(filepath, method, key_input, save_dir="output/decrypted"):
    with open(filepath, "rb") as f:
        raw = f.read()

    os.makedirs(save_dir, exist_ok=True)
    key = key_input.encode("latin1")  # biar bisa input hex/simbol dll

    try:
        if method == "xor":
            decrypted = xor_decrypt(raw, key)
            tag = f"custom_xor_{key_input}"
        elif method == "aes":
            if len(key) != 16:
                print("❌ Kunci AES harus 16 byte.")
                return None
            decrypted = aes_ecb_decrypt(raw, key)
            tag = f"custom_aes_{key_input}"
        else:
            print("❌ Metode tidak dikenali.")
            return None

        if not is_mostly_printable(decrypted[:1024]):
            print("⚠️ Hasil tidak tampak valid (bukan teks terbaca).")
            return None

        out_path = os.path.join(save_dir, f"{os.path.basename(filepath)}.{tag}.dec.txt")
        with open(out_path, "wb") as out:
            out.write(decrypted)
        return out_path
    except Exception as e:
        print(f"❌ Error: {e}")
        return None
