# scanner.py

import os
import hashlib
from tqdm import tqdm
import csv
import numpy as np
from decryptors.xor_decryptor import brute_force_xor
from decryptors.aes_ecb_decryptor import brute_force_aes_ecb
from decryptors.custom_decryptor import custom_decrypt

# Daftar ekstensi mencurigakan
SUSPICIOUS_EXTENSIONS = ['.enc', '.encrypted', '.locked', '.crypt', '.cry', '.crypted', '.aes']

# Magic bytes umum yang bukan plaintext
MAGIC_HEADERS = {
    b'\x50\x4B\x03\x04': 'ZIP/Docx',
    b'\x25\x50\x44\x46': 'PDF',
    b'\x89\x50\x4E\x47': 'PNG',
    b'\xFF\xD8\xFF': 'JPG',
    b'\x42\x4D': 'BMP',
    b'\x7F\x45\x4C\x46': 'ELF',
}

def is_suspicious_extension(filename):
    return any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

def check_magic_header(filepath):
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            for magic, desc in MAGIC_HEADERS.items():
                if header.startswith(magic):
                    return desc
            if all(c not in range(32, 127) for c in header):  # non-ASCII
                return "Unknown Binary"
    except Exception:
        return "Unreadable"
    return "Plaintext or Unknown"

def hash_file(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "Error"

def scan_folder(target_path, output_csv='output/scan_report.csv'):
    results = []

    def process_file(filepath):
        try:
            with open(filepath, 'rb') as f:
                raw = f.read(4096)  # hanya sebagian file

            size = os.path.getsize(filepath)
            ext_flag = is_suspicious_extension(filepath)
            header_type = check_magic_header(filepath)
            file_hash = hash_file(filepath)
            entropy = round(calculate_entropy(raw), 3)
            xor_flag = detect_xor_pattern(raw)
            aes_ecb_flag = detect_aes_ecb_pattern(raw)

            suspected = (
                ext_flag or 
                (header_type in ["Unknown Binary", "Unreadable"]) or 
                entropy > 7.5 or 
                xor_flag or 
                aes_ecb_flag
            )

            return {
                "File": os.path.basename(filepath),
                "Path": filepath,
                "Size(Bytes)": size,
                "Entropy": entropy,
                "XOR-Like": xor_flag,
                "AES-ECB-Like": aes_ecb_flag,
                "Suspicious Extension": ext_flag,
                "Header Type": header_type,
                "SHA256": file_hash,
                "Suspected Encrypted": suspected
            }
        except Exception as e:
            return None


    if os.path.isfile(target_path):
        print("🔍 Memindai file tunggal...")
        result = process_file(target_path)
        if result:
            results.append(result)

    elif os.path.isdir(target_path):
        print("🔍 Memindai folder...")
        for root, dirs, files in os.walk(target_path):
            for file in tqdm(files, desc="Scanning"):
                filepath = os.path.join(root, file)
                result = process_file(filepath)
                if result:
                    results.append(result)
    else:
        print("❌ Path tidak valid.")
        return

    if results:
        os.makedirs('output', exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\n✅ Scan selesai. Total file: {len(results)}. Laporan: {output_csv}")
    else:
        print("⚠️ Tidak ada file ditemukan atau diproses.")
def calculate_entropy(data: bytes) -> float:
    """Hitung entropy dari byte stream"""
    if not data:
        return 0.0
    byte_arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(byte_arr, minlength=256)
    probs = counts / len(data)
    probs = probs[probs > 0]
    entropy = -np.sum(probs * np.log2(probs))
    return entropy

def detect_xor_pattern(data: bytes) -> bool:
    """Deteksi apakah kemungkinan dienkripsi XOR dengan kunci tunggal"""
    if not data or len(data) < 1024:
        return False
    sample = data[:1024]
    unique = set(sample)
    return len(unique) < 10  # terlalu sedikit variasi byte

def detect_aes_ecb_pattern(data: bytes, block_size=16) -> bool:
    """Deteksi pola AES-ECB (blok identik berulang)"""
    if len(data) < block_size * 4:
        return False
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    num_blocks = len(blocks)
    num_unique = len(set(blocks))
    repetition_ratio = 1 - (num_unique / num_blocks)
    return repetition_ratio > 0.2  # ada pengulangan yang mencurigakan
     
if __name__ == "__main__":
    target = input("Masukkan path folder untuk discan: ").strip()
    if os.path.exists(target):
        scan_folder(target)
    else:
        print("❌ Folder tidak ditemukan.")

if __name__ == "__main__":
    target = input("Masukkan path file untuk didekripsi (XOR 1-byte): ").strip()
    if os.path.isfile(target):
        hasil = brute_force_xor(target)
        if hasil:
            print(f"\n✅ {len(hasil)} kemungkinan hasil dekripsi ditemukan:")
            for key, path in hasil:
                print(f"  [Key: {key:02x}] → {path}")
        else:
            print("⚠️ Tidak ada hasil dekripsi yang valid.")
    else:
        print("❌ File tidak ditemukan.")

if __name__ == "__main__":
    print("1. XOR Decryptor")
    print("2. AES-ECB Brute")
    pilihan = input("Pilih mode dekripsi: ")

    target = input("Masukkan path file terenkripsi: ").strip()
    if not os.path.isfile(target):
        print("❌ File tidak ditemukan.")
        exit()

    if pilihan == "1":
        hasil = brute_force_xor(target)
    elif pilihan == "2":
        hasil = brute_force_aes_ecb(target)
    else:
        print("❌ Pilihan tidak valid.")
        exit()

    if hasil:
        print(f"\n✅ {len(hasil)} kemungkinan hasil ditemukan:")
        for key, path in hasil:
            print(f"  [Key: {key}] → {path}")
    else:
        print("⚠️ Tidak ada hasil dekripsi valid.")
        
if __name__ == "__main__":
    print("1. XOR Decryptor")
    print("2. AES-ECB Brute")
    print("3. Custom Key Test")

    pilihan = input("Pilih mode dekripsi: ").strip()
    target = input("Masukkan path file terenkripsi: ").strip()

    if not os.path.isfile(target):
        print("❌ File tidak ditemukan.")
        exit()

    if pilihan == "1":
        hasil = brute_force_xor(target)
    elif pilihan == "2":
        hasil = brute_force_aes_ecb(target)
    elif pilihan == "3":
        mode = input("Metode? (xor / aes): ").strip().lower()
        key_input = input("Masukkan key manual: ").strip()
        out = custom_decrypt(target, mode, key_input)
        if out:
            print(f"✅ Hasil disimpan di: {out}")
        else:
            print("❌ Dekripsi gagal atau tidak valid.")
        exit()
    else:
        print("❌ Pilihan tidak valid.")
        exit()

    if hasil:
        print(f"\n✅ {len(hasil)} kemungkinan hasil ditemukan:")
        for key, path in hasil:
            print(f"  [Key: {key}] → {path}")
    else:
        print("⚠️ Tidak ada hasil dekripsi valid.")