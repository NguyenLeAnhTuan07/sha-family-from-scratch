import struct
import sys

#dịch trái
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    


def sha1(data: bytes) -> str:
    #khởi tạo giá trị
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #padding
    original_length = len(data) * 8
    data += b'\x80'
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'

    data += struct.pack('>Q', original_length)

    # ---------------------------
    # 3. Process each 512-bit block
    # ---------------------------
    for i in range(0, len(data), 64):
        block = data[i:i+64]

        # Break block into 16 words
        w = list(struct.unpack('>16I', block))

        # Extend to 80 words
        for t in range(16, 80):
            val = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]
            w.append(left_rotate(val, 1))

        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # ---------------------------
        # 4. Main loop (80 rounds)
        # ---------------------------
        for t in range(80):

            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[t]) & 0xffffffff

            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # ---------------------------
        # 5. Add this chunk to result
        # ---------------------------
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


#giao diện
def main():
    print("===== SHA-1 HASH TOOL =====")
    print("1. Hash plaintext")
    print("2. Hash file")
    choice = input("Choose option (1 or 2): ")

    if choice == "1":
        text = input("Enter plaintext: ")
        digest = sha1(text.encode())
        print("SHA-1:", digest)

    elif choice == "2":
        filename = input("Enter file path: ")
        try:
            with open(filename, "rb") as f:
                file_data = f.read()
            digest = sha1(file_data)
            print("SHA-1:", digest)
        except FileNotFoundError:
            print("File not found!")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()