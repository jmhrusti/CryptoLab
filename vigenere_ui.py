from tkinter import ttk
import pyperclip
import tkinter as tk

def load_tab(frame):
    # Create a frame to contain everything in the tab
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

    # Configure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")

    # Title
    title_label = ttk.Label(content_frame, text="Vigenere Cipher Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))
    
    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter your key:")
    label.grid(row=1, column=0, pady=(5, 2))  # Reduced the vertical padding here
    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=2, column=0, pady=(0,10))

    # Label and Text input for the message
    label2 = ttk.Label(content_frame, text="Enter message:")
    label2.grid(row=3, column=0, pady=(10, 5))  # Reduced the vertical padding here too
    message_input = tk.Text(content_frame, height=10, width=30)
    message_input.grid(row=4, column=0, pady=(0,10))

    # Create a frame to hold the buttons and center them
    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=5, column=0, pady=20)


    # Create a list to hold the result
    result = []

    # Encrypt button
    button1 = ttk.Button(button_frame, text="Encrypt", command=lambda: result.append(encrypt()))
    button1.grid(row=0, column=0, padx=5, pady=5)  # Use grid for alignment

    # Decrypt button
    button2 = ttk.Button(button_frame, text="Decrypt", command=lambda: result.append(decrypt()))
    button2.grid(row=0, column=1, padx=5, pady=5)

    # Copy button (to copy the result to clipboard)
    button4 = ttk.Button(button_frame, text="Copy", command=lambda: pyperclip.copy(str(result[-1])))
    button4.grid(row=0, column=3, padx=5, pady=5)  # Add the copy button

    # Output label (to display any feedback or action results)
    output_label = ttk.Label(content_frame, text="Results will be shown here", wraplength=200)
    output_label.grid(row=6, column=0, pady=10)

    # Ensure that the content frame resizes properly when the tab is resized
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)





    def encrypt():
        # Get key
        key = key_input.get().strip()
        
        # Get plaintext
        plain_text = message_input.get("1.0", tk.END).strip()
        
        # String for the encrypted text
        encrypted_text = ""
        
        # Start at the beginning of the key
        key_index = 0
        
        # Convert each character in plaintext and key to uppercase
        plain_text = plain_text.upper()
        key = key.upper()
        
        # For each character in plaintext get the encrypted character
        for char in plain_text:
            # Get the shift based on the current index of the key value
            shift = ord(key[key_index % len(key)]) - ord('A')
            
            # Append the encrypted letter based on the shift
            encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            
            # Increment the key index
            key_index += 1
        
        # Print results
        output_label.config(text=encrypted_text)
        return encrypted_text

    def decrypt():
        # Get key
        key = key_input.get().strip()
        
        # Get ciphertext
        cipher_text = message_input.get("1.0", tk.END).strip()
        
        # String for decrypted text
        decrypted_text = ""
        
        # Index of the key
        key_index = 0
        
        # Convert each character in ciphertext and key to uppercase
        cipher_text = cipher_text.upper()
        key = key.upper()
    
        # For each character in ciphertext get the decrypted character
        for char in cipher_text:
            # Get the shift based on the current index of the key value
            shift = ord(key[key_index % len(key)]) - ord('A')
            
            # Append the encrypted letter based on the shift
            decrypted_text += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            
            # Increment the key index
            key_index += 1
        
        # Print results
        output_label.config(text=decrypted_text)
        return decrypted_text