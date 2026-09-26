# BÀI TẬP MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN

- **Họ và tên:** Đào Tuấn Hưng
- **Mã số sinh viên:** K235480106032
- **Môn học:** An toàn và bảo mật thông tin

---

## 1. THUẬT TOÁN MÃ HÓA HIỆN ĐẠI DES VÀ AES

### 1.1. Thuật toán DES (Data Encryption Standard)
- **Tổng quan:** DES là thuật toán mã hóa đối xứng theo khối (Block Cipher), xử lý từng khối dữ liệu kích thước 64-bit sử dụng khóa có độ dài 56-bit (thực tế khóa nhận vào là 64-bit nhưng có 8-bit dùng để kiểm tra chẵn lẻ - parity bit).
- **Mô hình cấu trúc:** Dựa trên cấu trúc mạng Feistel 16 vòng (round).
- **Quy trình Mã hóa:**
1. **Hoán vị ban đầu (Initial Permutation - IP):** Khối dữ liệu 64-bit đầu vào được xáo trộn thứ tự các bit theo một bảng hoán vị cố định.
2. **16 vòng Feistel:** Dữ liệu 64-bit được chia thành 2 nửa: $L_0$ (Trái - 32 bit) và $R_0$ (Phải - 32 bit). Tại mỗi vòng $i$ (từ 1 đến 16):
     - $L_i = R_{i-1}$
     - $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$
     - Trong đó hàm $f$ thực hiện mở rộng 32-bit thành 48-bit, XOR với khóa con $K_i$ (48-bit), đi qua các hộp thay thế phi tuyến S-Box (biến 48-bit thành 32-bit) và hoán vị P-Box.
3. **Hoán vị nghịch đảo ($IP^{-1}$):** Kết hợp $R_{16}$ và $L_{16}$ rồi hoán vị ngược lại để tạo ra văn bản mã hóa (Ciphertext) 64-bit.
- **Quy trình Giải mã:** Sử dụng cùng một thuật toán và sơ đồ Feistel như mã hóa nhưng áp dụng các khóa con theo thứ tự ngược lại (từ $K_{16}$ giảm dần về $K_1$).

---

### 1.2. Thuật toán AES (Advanced Encryption Standard)
- **Tổng quan:** AES là thuật toán mã hóa đối xứng khối được thiết kế để thay thế DES do độ an toàn cao hơn hẳn. AES mã hóa khối dữ liệu cố định 128-bit với các độ dài khóa linh hoạt:
  - **AES-128:** Khóa 128-bit (10 vòng biến đổi).
  - **AES-192:** Khóa 192-bit (12 vòng biến đổi).
  - **AES-256:** Khóa 256-bit (14 vòng biến đổi).
- **Mô hình cấu trúc:** Dựa trên Mạng hoán vị thế (Substitution-Permutation Network - SPN), biến đổi ma trận trạng thái (State matrix) kích thước $4 \times 4$ byte.
- **Quy trình Mã hóa (Ví dụ với AES-128):**
1. **AddRoundKey ban đầu:** XOR ma trận trạng thái dữ liệu với khóa con đầu tiên.
2. **9 vòng lặp chuẩn (Vòng 1 đến vòng 9):**
     - **SubBytes:** Thay thế từng byte phi tuyến bằng bảng S-Box.
     - **ShiftRows:** Dịch chuyển vòng các hàng trong ma trận trạng thái (Hàng 0 giữ nguyên, Hàng 1 dịch 1 byte, Hàng 2 dịch 2 bytes, Hàng 3 dịch 3 bytes).
     - **MixColumns:** Trộn các cột bằng phép nhân ma trận trên trường Galois $GF(2^8)$.
     - **AddRoundKey:** XOR kết quả với khóa con của vòng hiện tại.
3. **Vòng cuối cùng (Vòng 10):** Bỏ qua bước *MixColumns*, chỉ thực hiện: `SubBytes` -> `ShiftRows` -> `AddRoundKey`.
- **Quy trình Giải mã:** Thực hiện các bước nghịch đảo theo thứ tự ngược lại: `InvAddRoundKey` -> `InvShiftRows` -> `InvSubBytes` -> `InvMixColumns` sử dụng các khóa con theo thứ tự từ vòng 10 về vòng 0.

---

### 1.3. Cài đặt thuật toán AES bằng ngôn ngữ Python
Mã nguồn cài đặt chương trình mã hóa và giải mã AES-128 (chế độ CBC) được lưu chi tiết trong file [`aes_demo.py`](./aes_demo.py).

---

## 2. THUẬT TOÁN MÃ HÓA BẤT ĐỐI XỨNG RSA

### 2.1. Giới thiệu
RSA là thuật toán mã hóa bất đối xứng (Public-key cryptography) dựa trên độ khó toán học của bài toán phân tích một số nguyên lớn thành tích của hai số nguyên tố.

### 2.2. Nguyên lý sinh cặp khóa (Public Key & Private Key)
Quá trình tạo cặp khóa RSA diễn ra theo 6 bước toán học:

1. **Chọn 2 số nguyên tố lớn ngẫu nhiên:** Chọn $p$ và $q$ ($p \neq q$).
2. **Tính tích $n$:** 
   $$n = p \times q$$
   *(Độ dài của $n$ chính là độ dài khóa RSA, ví dụ 2048-bit hoặc 409 Cryptographic bits).*
3. **Tính hàm số Euler $\phi(n)$:**
   $$\phi(n) = (p - 1)(q - 1)$$
4. **Chọn số nguyên công khai $e$:**
   - Chọn $e$ sao cho $1 < e < \phi(n)$ và $e$ nguyên tố cùng nhau với $\phi(n)$ (tức $gcd(e, \phi(n)) = 1$).
   - Trong thực tế, giá trị $e$ thường chọn cố định là $65537$ ($2^{16} + 1$).
5. **Tính số nguyên bí mật $d$:**
   - $d$ là nghịch đảo nhân modular của $e$ theo modulo $\phi(n)$, thỏa mãn phương trình:
     $$d \times e \equiv 1 \pmod{\phi(n)}$$
   - Số $d$ được tính nhanh bằng Thuật toán Euclid mở rộng.
6. **Thành phần cặp khóa thu được:**
   - **Khóa công khai (Public Key):** Cặp số $(e, n)$ - Được công khai cho mọi người dùng để mã hóa hoặc kiểm tra chữ ký.
   - **Khóa bí mật (Private Key):** Cặp số $(d, n)$ - Được giữ kín tuyệt đối bởi chủ sở hữu dùng để giải mã hoặc tạo chữ ký.

---

## 3. CÁC MÔ HÌNH ÁP DỤNG THUẬT TOÁN RSA VÀ KẾT HỢP VỚI AES

### 3.1. Các mô hình áp dụng thuật toán RSA

#### a. Mô hình Xác thực người nhận (Đảm bảo tính Bí mật - Confidentiality)
- **Mục đích:** Chỉ duy nhất người nhận hợp lệ mới đọc được nội dung thông điệp.
- **Quy trình:**
1. **Người gửi (Alice):** Sử dụng **Public Key của người nhận (Bob)** $(e_{Bob}, n_{Bob})$ để mã hóa thông điệp $M$:
     $$C = M^e \pmod n$$
2. **Người nhận (Bob):** Sử dụng **Private Key của chính mình** $(d_{Bob}, n_{Bob})$ để giải mã lấy lại thông điệp gốc $M$:
     $$M = C^d \pmod n$$

#### b. Mô hình Xác thực người gửi (Chữ ký số - Authentication / Non-repudiation)
- **Mục đích:** Xác minh chính xác ai là người gửi và đảm bảo dữ liệu không bị sửa đổi.
- **Quy trình:**
1. **Người gửi (Alice):** Băm thông điệp thành $H = Hash(M)$, sau đó dùng **Private Key của chính mình** $(d_{Alice}, n_{Alice})$ để mã hóa $H$ tạo ra Chữ ký số $S$:
     $$S = H^d \pmod n$$
2. **Người nhận (Bob):** Dùng **Public Key của Alice** $(e_{Alice}, n_{Alice})$ để giải mã chữ ký $S$ thu được $H'$. Sau đó tự băm lại $M$ thu được $H''$.
3. **Kiểm tra:** Nếu $H' == H''$, Bob xác nhận thông điệp đúng do Alice gửi và chưa bị can thiệp.

#### c. Mô hình Kết hợp cả Xác thực người gửi và người nhận
- **Mục đích:** Vừa giữ bí mật thông điệp, vừa xác thực danh tính người gửi.
- **Quy trình:**
1. **Alice ký:** Dùng *Private Key của Alice* ký lên thông điệp.
2. **Alice mã hóa:** Dùng *Public Key của Bob* mã hóa toàn bộ văn bản đã ký.
3. **Bob giải mã:** Dùng *Private Key của Bob* giải mã thông điệp.
4. **Bob xác minh:** Dùng *Public Key của Alice* để kiểm tra chữ ký.

---

### 3.2. So sánh thời gian mã hóa / giải mã giữa RSA và AES

| Tiêu chí so sánh | Thuật toán AES (Đối xứng) | Thuật toán RSA (Bất đối xứng) |
| :--- | :--- | :--- |
| **Loại mã hóa** | Mã hóa đối xứng (Symmetric) | Mã hóa bất đối xứng (Asymmetric) |
| **Tốc độ thực thi** | **Cực kỳ nhanh** (Nhanh hơn RSA từ 100 đến 1000 lần) | **Rất chậm** do phải thực hiện các phép tính số mũ modular $m^e \pmod n$ trên số lớn |
| **Kích thước dữ liệu** | Mã hóa được dữ liệu kích thước lớn bất kỳ (File, Video, Stream) | Chỉ mã hóa được văn bản ngắn (nhỏ hơn độ dài khóa RSA) |
| **Độ phức tạp tính toán** | Thấp, tối ưu hóa tốt ở mức phần cứng CPU | Rất cao, tốn nhiều bộ nhớ và CPU |
| **Quản lý khóa** | Khó khăn trong việc phân phối khóa bí mật an toàn | Dễ dàng chia sẻ khóa công khai công khai qua mạng |

---

### 3.3. Cách dùng kết hợp sức mạnh của RSA và AES (Mã hóa lai - Hybrid Encryption)

Vì **AES mã hóa dữ liệu lớn cực nhanh nhưng khó truyền khóa bí mật**, còn **RSA mã hóa chậm nhưng truyền khóa an toàn**, thực tế sử dụng mô hình **Mã hóa lai (Hybrid Cryptosystem)** (đang dùng trong HTTPS/SSL, PGP, TLS):



[ Dữ liệu lớn (Files/Message) ]                  [ Khóa phiên AES (Session Key) ]
                │                                                  │
                ▼                                                  ▼
         [ Mã hóa AES ]                                    [ Mã hóa RSA ]
        (Tốc độ cực nhanh)                             (Dùng Public Key Người Nhận)
                │                                                  │
                ▼                                                  ▼
 [ Dữ liệu đã mã hóa (Ciphertext) ]              [ Khóa phiên AES đã bị khóa bằng RSA ]
                └────────────────────────┬─────────────────────────┘
                                         ▼
                              ( Gửi qua Internet )

**Các bước thực hiện mô hình Hybrid:**
1. **Bước 1 (Sinh khóa phiên):** Người gửi tự động tạo ra một khóa AES ngẫu nhiên dùng 1 lần gọi là **Khóa phiên (Session Key)**.
2. **Bước 2 (Mã hóa dữ liệu):** Dùng thuật toán **AES** với *Session Key* để mã hóa toàn bộ dữ liệu/file dung lượng lớn.
3. **Bước 3 (Mã hóa khóa):** Dùng **Public Key RSA** của người nhận để mã hóa duy nhất chuỗi *Session Key* nhỏ gọn này.
4. **Bước 4 (Gửi đi):** Người gửi đóng gói và truyền cả `Dữ liệu đã mã hóa AES` + `Session Key đã mã hóa RSA` sang cho người nhận.
5. **Bước 5 (Giải mã phía người nhận):**
   - Người nhận dùng **Private Key RSA** của mình để giải mã lấy lại chuỗi *Session Key* ban đầu.
   - Dùng *Session Key* thu được để giải mã toàn bộ dữ liệu bằng thuật toán **AES**.
