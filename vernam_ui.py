from tkinter import ttk
import tkinter as tk
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
    title_label = ttk.Label(content_frame, text="Vernam Cipher Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))

    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter your key:")
    label.grid(row=1, column=0, pady=(5, 2))  # Reduced the vertical padding here
    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=2, column=0, pady=10)

    # Label and Text input for the message
    label2 = ttk.Label(content_frame, text="Enter message:")
    label2.grid(row=3, column=0, pady=(10, 5))  # Reduced the vertical padding here too
    message_input = tk.Text(content_frame, height=10, width=30)
    message_input.grid(row=4, column=0, pady=10)

    # Create a frame to hold the buttons and center them
    button_frame = ttk.Frame(content_frame)
    button_frame.grid(row=5, column=0, pady=20)


    # Create a list to hold the result
    result = []

    # Encrypt button
    button1 = ttk.Button(button_frame, text="Encrypt/Decrypt", command=lambda: result.append(encrypt_decrypt()))
    button1.grid(row=0, column=0, padx=5, pady=5)  # Use grid for alignment

    # Copy button (to copy the result to clipboard)
    button4 = ttk.Button(button_frame, text="Copy", command=lambda: pyperclip.copy(str(result[-1])))
    button4.grid(row=0, column=3, padx=5, pady=5)  # Add the copy button

    # Output label (to display any feedback or action results)
    output_label = ttk.Label(content_frame, text="Results will be shown here", wraplength=200)
    output_label.grid(row=6, column=0, pady=10)

    # Ensure that the content frame resizes properly when the tab is resized
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)



    #Function to make the key as long as the message
    def generate_key(message, key):
        #Makes key into a list of characters
        key = list(key)

        #Loop to make the key as long as the message
        for x in range(len(message) - len(key)):
            key.append(key[x % len(key)])  

        #Returns the key as a string, joining the characters of the list together with no spaces
        return "".join(key)

    def encrypt_decrypt():
        # Get key
        key = key_input.get().strip()
        
        # Get message
        message = message_input.get("1.0", tk.END)
        message = message[:-1]
        
        # Generate new key to make compatible with message
        key = generate_key(message, key)
        
        #List of encrypted/decrypted characters
        ciphertext = []

        for char, keyc in zip(message, key):

            # Encryption of each character
            cryptchar = (chr(ord(char) ^ ord(keyc)))
            
            #Ran into a problem where null character were causing problems, the following resolves the issue
            if cryptchar == '\x00':  
                cryptchar = ' '
                
            #Append each character
            ciphertext.append(cryptchar)
            
        # Display results
        output_label.config(text=ciphertext)
        result = ''.join(ciphertext)
        return result