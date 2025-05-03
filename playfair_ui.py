from tkinter import ttk
import pyperclip
import tkinter as tk

def load_tab(frame):
    global result
    # Create a frame to contain everything in the tab
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

    # Configure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")

    # Title
    title_label = ttk.Label(content_frame, text="Playfair Cipher Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))
    
    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter key word:")
    label.grid(row=1, column=0, pady=(5, 2))  # Reduced the vertical padding here
    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=2, column=0, pady=(0,10))

    # Label and Text input for the message
    label2 = ttk.Label(content_frame, text="Enter message:")
    label2.grid(row=3, column=0, pady=(5,2))  # Reduced the vertical padding here too
    message_input = tk.Text(content_frame, height=10, width=30)
    message_input.grid(row=4, column=0, pady=(0,10))

    # Create a frame to hold the buttons and center them
    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=5, column=0, pady=20)

    # Create a list to hold the result
    result = []

    # Encrypt button
    button1 = ttk.Button(button_frame, text="Encrypt", command=lambda: result.append(encrypt()))
    button1.grid(row=0, column=0, padx=5, pady=5)

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
        plaintext = message_input.get("1.0", tk.END).strip()
        
        # Encrypt messgae
        ciphertext = playfair_cipher(plaintext, key, 'encrypt')
        
        # Display results
        output_label.config(text=ciphertext)
        return ciphertext



    def decrypt():
        # Get key
        key = key_input.get().strip()
        
        # Get ciphertext
        ciphertext = message_input.get("1.0", tk.END).strip()
        
        # Decrypt messgae
        plaintext = playfair_cipher(ciphertext, key, 'decrypt')
        
        # Display results
        output_label.config(text=plaintext)
        return plaintext

    def playfair_cipher(plaintext, key, mode):
        # Alphabet for playfair cipher
        alphabet = 'abcdefghiklmnopqrstuvwxyz'
        
        # Get key input, replace all j's with i's
        key = key.lower().replace(' ', '').replace('j', 'i')
        
        # String for each unique letter in key
        key_square = ''
        
        # Add each unique letter from key to string
        for letter in key + alphabet:
            if letter not in key_square:
                key_square += letter
                
        # Replace all occurences of j with i for playfair cipher
        plaintext = plaintext.lower().replace(' ', '').replace('j', 'i')
        
        # Add dummy character is length of string is odd
        if len(plaintext) % 2 == 1:
            plaintext += 'x'
            
        # Create letter pairs for encryption/decryption
        digraphs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
        
        def encrypt(digraph):
            # Get each letter in the pair
            a, b = digraph
            
            # Get each letter's position
            row_a, col_a = divmod(key_square.index(a), 5)
            row_b, col_b = divmod(key_square.index(b), 5)
            
            # If letters are in the same row, shift right
            if row_a == row_b:
                col_a = (col_a + 1) % 5
                col_b = (col_b + 1) % 5
                
            # If letters are in the same column shift down
            elif col_a == col_b:
                row_a = (row_a + 1) % 5
                row_b = (row_b + 1) % 5
            
            # If neither, get letters in the opposite corner of the same row
            else:
                col_a, col_b = col_b, col_a
            return key_square[row_a*5 + col_a] + key_square[row_b*5 + col_b] 
        
        def decrypt(digraph):
            # Get each letter in pair
            a, b = digraph
            
            # Get each letter's position
            row_a, col_a = divmod(key_square.index(a), 5)
            row_b, col_b = divmod(key_square.index(b), 5)
            
            # If letters are in the same row, shift left
            if row_a == row_b:
                col_a = (col_a - 1) % 5
                col_b = (col_b - 1) % 5
                
            # If letters are in the same column shift down
            elif col_a == col_b:
                row_a = (row_a - 1) % 5
                row_b = (row_b - 1) % 5
                
            # If neither, get letters in the opposite corner of the same row
            else:
                col_a, col_b = col_b, col_a
            return key_square[row_a*5 + col_a] + key_square[row_b*5 + col_b]
        
        # String for final result
        result = ''
        
        # Add encryption/decryption for each letter pair to result
        for digraph in digraphs:
            if mode == 'encrypt':
                result += encrypt(digraph)
            elif mode == 'decrypt':
                result += decrypt(digraph)
        return result
