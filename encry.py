import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import tkinter as tk
from tkinter import filedialog, messagebox

BLOCK_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16

def pad(data):
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    if padding_length > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=100000)

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    enc_data = base64.b64encode(salt + iv + ciphertext)

    with open(file_path, 'wb') as f:
        f.write(enc_data)

    messagebox.showinfo("Success", "File encrypted successfully.")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        enc_data = base64.b64decode(f.read())

    try:
        salt = enc_data[:SALT_SIZE]
        iv = enc_data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
        ciphertext = enc_data[SALT_SIZE + BLOCK_SIZE:]
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))

        with open(file_path, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", "File decrypted successfully.")

    except (ValueError, KeyError) as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def ask_password(title, confirm=False):
    pw_window = tk.Toplevel()
    pw_window.title(title)
    pw_window.geometry("300x200" if confirm else "300x150")
    pw_window.configure(bg="#f0f0f0")
    pw_window.grab_set()

    tk.Label(pw_window, text="Enter Password:", bg="#f0f0f0", font=("Arial", 12)).pack(pady=10)
    password_entry = tk.Entry(pw_window, show="*", width=30, font=("Arial", 10))
    password_entry.pack()

    confirm_entry = None
    if confirm:
        tk.Label(pw_window, text="Confirm Password:", bg="#f0f0f0", font=("Arial", 12)).pack(pady=10)
        confirm_entry = tk.Entry(pw_window, show="*", width=30, font=("Arial", 10))
        confirm_entry.pack()

    password = []

    def submit():
        pw = password_entry.get()
        if confirm:
            confirm_pw = confirm_entry.get()
            if pw != confirm_pw:
                messagebox.showerror("Error", "Passwords do not match!")
                return
        password.append(pw)
        pw_window.destroy()

    tk.Button(pw_window, text="Submit", command=submit, bg="#4CAF50", fg="white", font=("Arial", 10), width=10).pack(pady=15)
    pw_window.wait_window()
    return password[0] if password else None

def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = ask_password("Encryption Password", confirm=True)
        if password:
            encrypt_file(file_path, password)

def select_file_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = ask_password("Decryption Password")
        if password:
            decrypt_file(file_path, password)

def main():
    root = tk.Tk()
    root.title("AES-256 File Encryptor/Decryptor")
    root.geometry("350x220")
    root.configure(bg="#e6f2ff")

    tk.Label(root, text="AES-256 File Encryptor/Decryptor", font=("Helvetica", 14, "bold"), bg="#e6f2ff").pack(pady=20)

    tk.Button(root, text="Encrypt File", command=select_file_encrypt, width=25, height=2, bg="#008CBA", fg="white").pack(pady=10)
    tk.Button(root, text="Decrypt File", command=select_file_decrypt, width=25, height=2, bg="#f44336", fg="white").pack(pady=10)

    root.mainloop()

if __name__ == '__main__':
    main()
