import tkinter as tk
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import pyperclip

def load_tab(frame):
    # Create a frame to contain everything in the tab
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

    # Configure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")

    # Title
    title_label = ttk.Label(content_frame, text="AES Encryption Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))

    # AES Modes dropdown options
    aes_modes = ["ECB", "CBC", "CTR"]

    # AES Mode Label and Dropdown
    mode_label = ttk.Label(content_frame, text="Select AES Block Mode:")
    mode_label.grid(row=1, column=0, pady=(5, 2))

    mode_dropdown = ttk.Combobox(content_frame, values=aes_modes, width=28)
    mode_dropdown.grid(row=2, column=0, pady=(0, 10))
    mode_dropdown.set(aes_modes[0])  # Default mode

    # Key input
    key_label = ttk.Label(content_frame, text="Enter 16 character AES key value:")
    key_label.grid(row=3, column=0, pady=(5, 2))

    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=4, column=0, pady=(0, 10))

    # IV or Nonce input
    iv_label = ttk.Label(content_frame, text="Enter your IV or nonce value:")
    iv_label.grid(row=5, column=0, pady=(5, 2))

    iv_input = ttk.Entry(content_frame, width=30)
    iv_input.grid(row=6, column=0, pady=(0, 10))

    # Message input
    message_label = ttk.Label(content_frame, text="Enter message:")
    message_label.grid(row=7, column=0, pady=(5, 2))

    message_input = tk.Text(content_frame, height=10, width=30)
    message_input.grid(row=8, column=0, pady=(0, 10))

    # Button Frame
    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=9, column=0, pady=15)

    result = []

    # Output label
    output_label = ttk.Label(content_frame, text="Results will be shown here", wraplength=200)
    output_label.grid(row=10, column=0, pady=10)

    # ====================== ENCRYPTION/DECRYPTION LOGIC ======================

    def pad(data, block_size=16):
        padding_length = block_size - (len(data) % block_size)
        return data + bytes([padding_length] * padding_length)

    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    def encrypt_ecb(plaintext, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = pad(plaintext.encode())
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return binascii.hexlify(ciphertext).decode()

    def decrypt_ecb(ciphertext_hex, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        ciphertext = binascii.unhexlify(ciphertext_hex)
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return unpad(decrypted).decode()

    def encrypt_cbc(plaintext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = pad(plaintext.encode())
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return binascii.hexlify(ciphertext).decode()

    def decrypt_cbc(ciphertext_hex, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        ciphertext = binascii.unhexlify(ciphertext_hex)
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return unpad(decrypted).decode()

    def encrypt_ctr(plaintext, key, nonce):
        cipher = Cipher(algorithms.AES(key), CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return binascii.hexlify(ciphertext).decode()

    def decrypt_ctr(ciphertext_hex, key, nonce):
        cipher = Cipher(algorithms.AES(key), CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        ciphertext = binascii.unhexlify(ciphertext_hex)
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()

    def validate_input(key, message):
        if not key.strip():
            return "Error: Key must be entered."
        if not message.strip():
            return "Error: Message must be entered."
        return None

    # ====================== BUTTON COMMAND FUNCTIONS ======================

    def encrypt_command():
        key = key_input.get().strip().encode('utf-8')
        ivn = iv_input.get().strip().encode('utf-8')
        message = message_input.get("1.0", tk.END).strip()
        selected_mode = mode_dropdown.get()
        error = validate_input(key, message)

        if error:
            output_label.config(text=error)
            return

        try:
            if selected_mode == "ECB":
                output = encrypt_ecb(message, key)
            elif selected_mode == "CBC":
                output = encrypt_cbc(message, key, ivn)
            elif selected_mode == "CTR":
                output = encrypt_ctr(message, key, ivn)
            output_label.config(text=output)
            result.append(output)
        except Exception as e:
            output_label.config(text=f"Encryption error: {e}")

    def decrypt_command():
        key = key_input.get().strip().encode('utf-8')
        ivn = iv_input.get().strip().encode('utf-8')
        message = message_input.get("1.0", tk.END).strip()
        selected_mode = mode_dropdown.get()
        error = validate_input(key, message)

        if error:
            output_label.config(text=error)
            return

        try:
            if selected_mode == "ECB":
                output = decrypt_ecb(message, key)
            elif selected_mode == "CBC":
                output = decrypt_cbc(message, key, ivn)
            elif selected_mode == "CTR":
                output = decrypt_ctr(message, key, ivn)
            output_label.config(text=output)
            result.append(output)
        except Exception as e:
            output_label.config(text=f"Decryption error: {e}")

    # ====================== BUTTONS ======================

    encrypt_button = ttk.Button(button_frame, text="Encrypt", command=encrypt_command)
    encrypt_button.grid(row=0, column=0, padx=5, pady=5)

    decrypt_button = ttk.Button(button_frame, text="Decrypt", command=decrypt_command)
    decrypt_button.grid(row=0, column=1, padx=5, pady=5)

    copy_button = ttk.Button(button_frame, text="Copy", command=lambda: pyperclip.copy(str(result[-1])))
    copy_button.grid(row=0, column=2, padx=5, pady=5)
