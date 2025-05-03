from tkinter import ttk
import tkinter as tk
import numpy as np
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
    title_label = ttk.Label(content_frame, text="Hill Cipher Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))
    
    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter a 4 letter key:")
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
    button_frame.grid(row=5, column=0, pady=15)

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


    #Function to find the modular inverse of a number (for part 1 of the inversion equation)
    def mod_inverse(determinance):
        #Trys all values 0-25
        for x in range(1, 26):
            #Checks to see if x is the modular inverse of determinance
            if (determinance * x) % 26 == 1:
                return x
        return None

    #Function to find the modular inverse of a matrix
    def matrix_inverse(matrix):
        #Calculate the determinant of the matrix
        determinance = int(np.round(np.linalg.det(matrix)))
        #Get the modular inverse of the function
        det_inv = mod_inverse(determinance)
        #Throws an error if no modular inverse is found
        if det_inv is None:
            raise ValueError("Matrix is not invertible")

        #Calculate the swapped matrix with the modular inverse
        swapped = np.round(np.linalg.inv(matrix) * determinance).astype(int)
        #Multiply the inverse with the new matrix to ger the inverse matrix
        return (det_inv * swapped) % 26

    #Convert characters to numbers
    def char_to_num(char):
        if char.islower():
            return ord(char) - ord('a')
        elif char.isupper():
            return ord(char) - ord('A')
        return None

    #Convert numbers to characters
    def num_to_char(num):
        return chr(num + ord('a'))

    #Encrypt message with Hill Cipher
    def encrypt():
        #Get inputs from GUI
        key = key_input.get().strip()
        if len(key) != 4:
            output_label.config(text=f"Key must be 4 characters long. Please try again.")
        message = message_input.get("1.0", tk.END).strip()

        #Convert the key into a 2x2 matrix
        keynums = [char_to_num(value) for value in key]
        encryptkey = np.array(keynums).reshape(2, 2)


        #Convert message into numbers
        messagenums = [char_to_num(char) for char in message if char.isalpha()]
        if len(messagenums) % 2 != 0:
            messagenums.append(char_to_num('x'))  #Append X to the end of the message if the message is not divisible by 2

        #Convert the message into blocks of two chars to make it easier for encrypting
        blocks = [messagenums[i:i+2] for i in range(0, len(messagenums), 2)]

        encryptedchars = []

        #Encrypt each block
        for block in blocks:
            part1 = encryptkey[0][0] * block[0] + encryptkey[0][1] * block[1]
            part2 = encryptkey[1][0] * block[0] + encryptkey[1][1] * block[1]

            encryptedchars.append(int(part1 % 26))
            encryptedchars.append(int(part2 % 26))


        #Convert the encrypted values into characters for ciphertext
        ciphertext = ''.join([num_to_char(z) for z in encryptedchars])

        #Show encrypted ciphertext as output
        output_label.config(text=f"Encrypted Ciphertext: {ciphertext}")
        return ciphertext

    #Decrypt message with Hill Cipher
    def decrypt():
        # Get inputs from the GUI
        key = key_input.get().strip()
        if len(key) != 4:
            output_label.config(text="Key must be 4 characters long. Please try again.")
            return  # Early return if key length is incorrect
        
        message = message_input.get("1.0", tk.END).strip()
        if len(message) == 0:
            output_label.config(text="Message cannot be empty. Please enter a message.")
            return  # Early return if no message is entered

        try:
            # Convert the key into a 2x2 matrix
            keynums = [char_to_num(value) for value in key]
            encryptkey = np.array(keynums).reshape(2, 2)

            # Find the inverse matrix of the key
            inverse_matrix = matrix_inverse(encryptkey)

            # Convert ciphertext into numbers
            messagenums = [char_to_num(char) for char in message if char.isalpha()]

            # Convert the message into blocks of two chars for decrypting
            blocks = [messagenums[i:i + 2] for i in range(0, len(messagenums), 2)]

            decryptedchars = []

            # Decrypt each block
            for block in blocks:
                part1 = inverse_matrix[0][0] * block[0] + inverse_matrix[0][1] * block[1]
                part2 = inverse_matrix[1][0] * block[0] + inverse_matrix[1][1] * block[1]

                decryptedchars.append(int(part1 % 26))
                decryptedchars.append(int(part2 % 26))

            # Convert the decrypted numbers back into characters
            plaintext = ''.join([num_to_char(val) for val in decryptedchars])

            # Show decrypted plaintext as output
            output_label.config(text=f"Decrypted Plaintext: {plaintext}")
            return plaintext  # Returning the plaintext for any further use

        except ValueError as e:
            # If a ValueError (e.g., non-invertible matrix) occurs, display the error message
            output_label.config(text=f"Error: {str(e)}")
            return  # Return early in case of error
        
        except Exception as e:
            # Catch all other exceptions (for example, if decryption fails for another reason)
            output_label.config(text=f"An unexpected error occurred: {str(e)}")
            return
