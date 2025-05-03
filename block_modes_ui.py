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

    # Set column and row configuration for centering content
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")
    content_frame.grid_rowconfigure(0, weight=1)
    
    # AES Modes dropdown options
    aes_modes = ["ECB", "CBC", "CTR"]  # AES block modes

    # Label for the AES mode dropdown
    mode_label = ttk.Label(content_frame, text="Select AES Block Mode:")
    mode_label.grid(row=0, column=0, pady=(5, 2))  
    mode_dropdown = ttk.Combobox(content_frame, values=aes_modes, width=28)
    mode_dropdown.grid(row=1, column=0, pady=10)
    mode_dropdown.set(aes_modes[0])  # Default to ECB mode
    selected_mode = mode_dropdown.get()

    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter 16 character AES key value:")
    label.grid(row=2, column=0, pady=(5, 2))  # Reduced the vertical padding here
    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=3, column=0, pady=10)
    
    #In for IV or nonce
    label = ttk.Label(content_frame, text="Enter your IV or nonce value:")
    label.grid(row=4, column=0, pady=(5, 2))  # Reduced the vertical padding here
    iv_input = ttk.Entry(content_frame, width=30)
    iv_input.grid(row=5, column=0, pady=10)

    # Label and Text input for the message
    label2 = ttk.Label(content_frame, text="Enter message:")
    label2.grid(row=6, column=0, pady=(10, 5))  # Reduced the vertical padding here
    message_input = tk.Text(content_frame, height=10, width=30)
    message_input.grid(row=7, column=0, pady=10)

    # Create a frame to hold the buttons and center them
    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=8, column=0, pady=20)

    result = []

    # Encrypt button
    button1 = ttk.Button(button_frame, text="Encrypt", command=lambda: result.append(encrypt(selected_mode)))
    button1.grid(row=0, column=0, padx=5, pady=5)

    # Decrypt button
    button2 = ttk.Button(button_frame, text="Decrypt", command=lambda: result.append(decrypt(selected_mode)))
    button2.grid(row=0, column=1, padx=5, pady=5)

    # Copy button (to copy the result to clipboard)
    button4 = ttk.Button(button_frame, text="Copy", command=lambda: pyperclip.copy(str(result[-1])))
    button4.grid(row=0, column=3, padx=5, pady=5)  # Add the copy button

    # Output label (to display any feedback or action results)
    output_label = ttk.Label(content_frame, text="Results will be shown here", wraplength=200)
    output_label.grid(row=9, column=0, pady=10)

    # Ensure that the content frame resizes properly when the tab is resized
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)


    # Pad the data
    def pad(data, block_size=16):
        padding_length = block_size - (len(data) % block_size)
        return data + bytes([padding_length] * padding_length)

    # Unpad the data
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    #ECB Code
    def encrypt_ecb(plaintext, key):
        # Create a Cipher object using AES in ECB mode with the  key
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

        # Create an encryptor from the cipher
        encryptor = cipher.encryptor()

        # Pad the plaintext to make it a multiple of AES's 16-byte block size
        padded_plaintext = pad(plaintext.encode())

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return the ciphertext as a hexadecimal string
        return binascii.hexlify(ciphertext).decode()

    def decrypt_ecb(ciphertext_hex, key):
        # Create a Cipher object for decryption using AES in ECB mode
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

        # Create a decryptor from the cipher
        decryptor = cipher.decryptor()

        # Convert the hex string back to raw bytes
        ciphertext = binascii.unhexlify(ciphertext_hex)

        # Decrypt the ciphertext to get the padded plaintext
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove the padding and decode to get the plaintext
        return unpad(decrypted_padded).decode()

    #CBC Code
    def encrypt_cbc(plaintext, key, iv):
        # Create a Cipher object using AES encryption in CBC mode with the  key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # Create an encryptor object from the cipher
        encryptor = cipher.encryptor()

        # Pad the plaintext to make its length a multiple of the block size (AES uses 16-byte blocks)
        padded_plaintext = pad(plaintext.encode())

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Convert the ciphertext to a hexadecimal string for easier storage or transmission
        return binascii.hexlify(ciphertext).decode()

    def decrypt_cbc(ciphertext_hex, key, iv):
        # Create a Cipher object using AES decryption in CBC mode with the same key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # Create a decryptor object from the cipher
        decryptor = cipher.decryptor()

        # Convert the hex string back to raw bytes
        ciphertext = binascii.unhexlify(ciphertext_hex)

        # Decrypt the ciphertext to get the padded plaintext
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove the padding to get the plaintext
        return unpad(decrypted_padded).decode()

    #CTR Code
    def encrypt_ctr(plaintext, key, nonce):
        # Create a Cipher object using AES in CTR mode with the given key and nonce
        cipher = Cipher(algorithms.AES(key), CTR(nonce), backend=default_backend())

        # Create an encryptor object from the cipher
        encryptor = cipher.encryptor()

        # Encrypt the plaintext directly (no padding needed in CTR mode)
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        # Convert the ciphertext to a hexadecimal string for easier transmission/storage
        return binascii.hexlify(ciphertext).decode()

    def decrypt_ctr(ciphertext_hex, key, nonce):
        # Create a Cipher object using AES in CTR mode with the same key and nonce
        cipher = Cipher(algorithms.AES(key), CTR(nonce), backend=default_backend())

        # Create a decryptor object from the cipher
        decryptor = cipher.decryptor()

        # Convert the hexadecimal ciphertext back to bytes
        ciphertext = binascii.unhexlify(ciphertext_hex)

        # Decrypt the ciphertext (CTR mode decryption is identical to encryption)
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

        # Convert decrypted bytes back to string
        return decrypted_text.decode()

    # Function to ensure valid inputs
    def validate_input(key, message):
        if not key.strip():
            return "Error: Key must be entered."
        if not message.strip():
            return "Error: Message must be entered."
        return None
    
    # Function to encrypt using the selected AES mode
    def encrypt(selected_mode):
        # Get the key, the IV, and the message
        key = key_input.get().strip()
        key = key.encode('utf-8')  # Convert to bytes
        ivn = iv_input.get().strip().encode('utf-8')
        message = message_input.get("1.0", tk.END).strip()
        
        # Validate the input
        error = validate_input(key, message)
        
        # Get the selected block mode
        selected_mode = mode_dropdown.get()
        if error:
            output_label.config(text=error)
        else:
            if selected_mode == "ECB":
                result = encrypt_ecb(message, key)
            elif selected_mode == "CBC":
                result = encrypt_cbc(message, key, ivn)
            elif selected_mode == "CTR":
                result = encrypt_ctr(message, key, ivn)
                
        # Display results
        output_label.config(text=result)
        return result

    # Function to decrypt using the selected AES mode
    def decrypt(selected_mode):
        # Get the key, IV, and message
        key = key_input.get().strip()
        key = key.encode('utf-8')  # Convert to bytes
        ivn = iv_input.get().strip().encode('utf-8')
        message = message_input.get("1.0", tk.END).strip()
        
        # Check for valid input
        error = validate_input(key, message)
        
        # Get selected block mode
        selected_mode = mode_dropdown.get()
        if error:
            output_label.config(text=error)
        else:
            if selected_mode == "ECB":
                result = decrypt_ecb(message, key)
            elif selected_mode == "CBC": 
                result = decrypt_cbc(message, key, ivn)
            elif selected_mode == "CTR":
                result = decrypt_ctr(message, key, ivn)
                
        # Display results
        output_label.config(text=result)
        return result
