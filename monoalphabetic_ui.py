from tkinter import ttk
import tkinter as tk
import pyperclip

def load_tab(frame):
    input_dict = {}
    input_boxes = {}

    # Create a frame to contain everything in the tab
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

    # Configure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")
    
    # Title
    title_label = ttk.Label(content_frame, text="Monoalphabetic Cipher", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 10))

    # Key input grid
    key_frame = ttk.Frame(content_frame)
    key_frame.grid(row=1, column=0, pady=10)

    # Generate input boxes for each letter
    for i, letter in enumerate("abcdefghijklmnopqrstuvwxyz"):
        label = ttk.Label(key_frame, text=letter)
        label.grid(row=i // 13, column=(i % 13) * 2, padx=2, pady=2)
        entry = ttk.Entry(key_frame, width=3)
        entry.grid(row=i // 13, column=(i % 13) * 2 + 1, padx=2, pady=2)
        input_boxes[letter] = entry
        input_dict[letter] = ""

    # Funcdtion to update dictionary
    def update_dict():
        for x in input_dict:
            input_dict[x] = input_boxes[x].get().lower()

    # Button to update dictionary
    update_button = ttk.Button(content_frame, text="Create Key", command=update_dict)
    update_button.grid(row=2, column=0, pady=10)

    # Message for user to enter message
    message_label = ttk.Label(content_frame, text="Enter message:")
    message_label.grid(row=3, column=0, pady=(10, 2))

    # Message input box
    message_input = tk.Text(content_frame, height=8, width=60)
    message_input.grid(row=4, column=0, pady=10)

    # Output for encrypted/decrypted text
    output_label = ttk.Label(content_frame, text="", wraplength=500, foreground="white")
    output_label.grid(row=6, column=0, pady=10)

    result = [""]

    def encrypt():
        # Update dictionary with new letters
        update_dict()
        
        # Gets message input
        message = message_input.get("1.0", tk.END).strip()
        
        # Get each letter in the message
        separated = list(message)
        
        # Convert each letter to new letter
        converted = [input_dict.get(ch.lower(), ch) if ch.isalpha() else ch for ch in separated]
        
        # Create ciphertext
        ciphertext = ''.join(converted)
        
        # Print result
        output_label.config(text=f"Encrypted Ciphertext:\n{ciphertext}")
        result[0] = ciphertext

    def decrypt():
        reversed_dict = {v: k for k, v in input_dict.items()}
        
        # Get message input
        message = message_input.get("1.0", tk.END).strip()
        
        # Get each letter in message
        separated = list(message)
        
        # Convert each letter to new letter
        converted = [reversed_dict.get(ch.lower(), ch) if ch.isalpha() else ch for ch in separated]
        
        # Create original plaintext
        plaintext = ''.join(converted)
        
        # Print results
        output_label.config(text=f"Decrypted Plaintext:\n{plaintext}")
        result[0] = plaintext

    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=5, column=0, pady=10)

    # Encrypt button
    encrypt_btn = ttk.Button(button_frame, text="Encrypt", command=encrypt)
    encrypt_btn.pack(side=tk.LEFT, padx=5)

    # Decrypt button
    decrypt_btn = ttk.Button(button_frame, text="Decrypt", command=decrypt)
    decrypt_btn.pack(side=tk.LEFT, padx=5)

    # Copy message button
    copy_btn = ttk.Button(button_frame, text="Copy", command=lambda: pyperclip.copy(str(result[0])))
    copy_btn.pack(side=tk.LEFT, padx=5)
