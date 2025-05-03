import tkinter as tk
from tkinter import ttk
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
    title_label = ttk.Label(content_frame, text="Caesar Cipher Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))

    # Key Input
    key_label = ttk.Label(content_frame, text="Enter numerical key value:")
    key_label.grid(row=1, column=0, pady=(5, 2))

    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=2, column=0, pady=(0, 10))

    # Message Input
    message_label = ttk.Label(content_frame, text="Enter message:")
    message_label.grid(row=3, column=0, pady=(5, 2))

    message_input = tk.Text(content_frame, height=10, width=30)
    message_input.grid(row=4, column=0, pady=(0, 10))

    # Button Frame
    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=5, column=0, pady=15)

    # Result List
    result = []

    # Output Label
    output_label = ttk.Label(content_frame, text="Results will be shown here", wraplength=200)
    output_label.grid(row=6, column=0, pady=10)

    # Caesar Cipher Dictionaries
    Dict = {chr(i): (i - 97) for i in range(97, 123)}
    Dict.update({chr(i): (i - 65) for i in range(65, 91)})
    Dict[" "] = 1000

    reversed_dict = {v: k for k, v in Dict.items()}
    reversed_dict[1000] = " "

    # ========== Utility Functions ==========

    def validate_input(key, message):
        if not key.strip():
            return "Error: Key must be entered."
        if not message.strip():
            return "Error: Message must be entered."
        if not key.isdigit():
            return "Error: Key must be an integer."
        return None

    def validate_message(message):
        if not message.strip():
            return "Error: Message must be entered."
        return None

    def calculate_encrypt(key, message):
        separated = list(message.strip())
        original_vals = [Dict.get(c, c) for c in separated]
        new_vals = [(i + key) % 26 if i != 1000 else i for i in original_vals]
        chars = [reversed_dict.get(i, i) for i in new_vals]
        return ''.join(chars)

    def calculate_decrypt(key, message):
        separated = list(message.strip())
        original_vals = [Dict.get(c, c) for c in separated]
        new_vals = [(i - key) % 26 if i != 1000 else i for i in original_vals]
        chars = [reversed_dict.get(i, i) for i in new_vals]
        return ''.join(chars)

    # ========== Cipher Actions ==========

    def encrypt_command():
        key = key_input.get().strip()
        message = message_input.get("1.0", tk.END).strip()
        error = validate_input(key, message)

        if error:
            output_label.config(text=error)
            return

        key = int(key)
        ciphertext = calculate_encrypt(key, message)
        result_text = f"Encrypted Ciphertext: {ciphertext}"
        output_label.config(text=result_text)
        result.append(ciphertext)

    def decrypt_command():
        key = key_input.get().strip()
        message = message_input.get("1.0", tk.END).strip()
        error = validate_input(key, message)

        if error:
            output_label.config(text=error)
            return

        key = int(key)
        plaintext = calculate_decrypt(key, message)
        result_text = f"Decrypted Plaintext: {plaintext}"
        output_label.config(text=result_text)
        result.append(plaintext)

    def brute_force_command():
        message = message_input.get("1.0", tk.END).strip()
        error = validate_message(message)

        if error:
            output_label.config(text=error)
            return

        possibilities = [f"Key {k}: {calculate_decrypt(k, message)}" for k in range(1, 26)]
        result_text = "Brute Force Results:\n" + "\n".join(possibilities)
        output_label.config(text=result_text)
        result.append(possibilities)

    def copy_command():
        if result:
            pyperclip.copy(str(result[-1]))

    # ========== Buttons ==========

    encrypt_button = ttk.Button(button_frame, text="Encrypt", command=encrypt_command)
    encrypt_button.grid(row=0, column=0, padx=5, pady=5)

    decrypt_button = ttk.Button(button_frame, text="Decrypt", command=decrypt_command)
    decrypt_button.grid(row=0, column=1, padx=5, pady=5)

    brute_force_button = ttk.Button(button_frame, text="Brute Force", command=brute_force_command)
    brute_force_button.grid(row=0, column=2, padx=5, pady=5)

    copy_button = ttk.Button(button_frame, text="Copy", command=copy_command)
    copy_button.grid(row=0, column=3, padx=5, pady=5)
