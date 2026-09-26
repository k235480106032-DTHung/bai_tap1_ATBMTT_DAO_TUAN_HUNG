"""
CÀI ĐẶT THUẬT TOÁN MÃ HÓA AES-128 (MÔ HÌNH CBC)
Họ và tên: Đào Tuấn Hưng
MSSV: K235480106032
Môn học: An toàn và bảo mật thông tin
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def main():
    print("==================================================")
    print("   DEMO THUẬT TOÁN MÃ HÓA & GIẢI MÃ AES-128 CBC   ")
    print("   Thực hiện: Đào Tuấn Hưng - K235480106032       ")
    print("==================================================\n")

    # 1. Khởi tạo khóa 128-bit (16 bytes) ngẫu nhiên
    key = os.urandom(16)
    print(f"[1] Khóa bí mật AES (128-bit / Hex): {key.hex()}")

    # 2. Thông điệp ban đầu cần mã hóa
    plaintext = "Xin chào thầy! Em là Đào Tuấn Hưng (K235480106032) thực hiện bài tập AES.".encode('utf-8')
    print(f"[2] Thông điệp gốc (Plaintext): {plaintext.decode('utf-8')}")

    # 3. Quá trình Mã hóa (Encryption)
    cipher_encrypt = AES.new(key, AES.MODE_CBC)
    iv = cipher_encrypt.iv  # Vector khởi tạo Initialization Vector (16 bytes)
    
    # Đệm dữ liệu (Padding) để đạt kích thước khối 16 bytes và tiến hành mã hóa
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher_encrypt.encrypt(padded_plaintext)
    
    print(f"[3] Vector khởi tạo IV (Hex): {iv.hex()}")
    print(f"[4] Dữ liệu đã mã hóa (Ciphertext Hex): {ciphertext.hex()}\n")

    # 4. Quá trình Giải mã (Decryption)
    cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_padded = cipher_decrypt.decrypt(ciphertext)
    decrypted_plaintext = unpad(decrypted_padded, AES.block_size)

    print(f"[5] Dữ liệu sau khi giải mã: {decrypted_plaintext.decode('utf-8')}")
    print("==================================================")

if __name__ == "__main__":
    main()