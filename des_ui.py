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
    title_label = ttk.Label(content_frame, text="DES Encryption", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))
    
    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter 8 character key:")
    label.grid(row=1, column=0, pady=(5, 2))  # Reduced the vertical padding here
    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=2, column=0, pady=(0, 10))

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
    button1 = ttk.Button(button_frame, text="Encrypt", command=lambda: result.append(onencrypt()))
    button1.grid(row=0, column=0, padx=5, pady=5)  # Use grid for alignment

    # Decrypt button
    button2 = ttk.Button(button_frame, text="Decrypt", command=lambda: result.append(ondecrypt()))
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

    def onencrypt():
        key = key_input.get().strip()
        key = ''.join(format(ord(char), '08b') for char in key)  # Convert key to binary

        message = message_input.get("1.0", tk.END).strip()

        # Break the message into 64-bit (8-character) chunks
        message_blocks = [message[i:i+8] for i in range(0, len(message), 8)]

        encrypted_blocks = []
        for block in message_blocks:
            block_bin = ''.join(format(ord(char), '08b') for char in block)  # Convert block to binary

            #  Padding to ensure 64-bit block
            if len(block_bin) < 64:
                block_bin = block_bin.ljust(64, '0')  # pad with 0s to the right

            encrypted_block = Encrypt(block_bin, key)  # Encrypt the block
            encrypted_blocks.append(encrypted_block)

        # Join the encrypted blocks back together into one string
        encrypted_message = ''.join(encrypted_blocks)

        # Convert the binary string back to characters
        result = ''.join(chr(int(encrypted_message[i:i+8], 2)) for i in range(0, len(encrypted_message), 8))

        # Display the result in the label
        output_label.config(text=result)
        return result


    def ondecrypt():
        key = key_input.get().strip()
        key = ''.join(format(ord(char), '08b') for char in key)  # Convert key to binary
        
        message = message_input.get("1.0", tk.END).strip()
        
        # Convert message into binary string
        message_bin = ''.join(format(ord(char), '08b') for char in message)
        
        # Break the message into 64-bit (8-character) chunks
        message_blocks = [message_bin[i:i+64] for i in range(0, len(message_bin), 64)]
        
        decrypted_blocks = []
        for block in message_blocks:
            decrypted_block = Decrypt(block, key)  # Decrypt the block
            decrypted_blocks.append(decrypted_block)
        
        # Join the decrypted blocks back together into one string
        decrypted_message = ''.join(decrypted_blocks)
        
        # Convert the binary string back to characters
        result = ''.join(chr(int(decrypted_message[i:i+8], 2)) for i in range(0, len(decrypted_message), 8))
        
        # Display the result in the label
        output_label.config(text=result)
        return result





    # Defines all tables to use in permutation functions
    Fpermutation = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    IPpermutation = [58, 50, 42, 34, 26, 18, 10, 2,60, 52, 44, 36, 28, 20, 12, 4,62, 54, 46, 38, 30, 22, 14, 6,64, 56, 48, 40, 32, 24, 16, 8,57, 49, 41, 33, 25, 17, 9, 1,59, 51, 43, 35, 27, 19, 11, 3,61, 53, 45, 37, 29, 21, 13, 5,63, 55, 47, 39, 31, 23, 15, 7]
    FPpermutation = [40, 8, 48, 16, 56, 24, 64, 32,39, 7, 47, 15, 55, 23, 63, 31,38, 6, 46, 14, 54, 22, 62, 30,37, 5, 45, 13, 53, 21, 61, 29,36, 4, 44, 12, 52, 20, 60, 28,35, 3, 43, 11, 51, 19, 59, 27,34, 2, 42, 10, 50, 18, 58, 26,33, 1, 41, 9, 49, 17, 57, 25]
    Pairity_Remove = [57, 49, 41, 33, 25, 17, 9, 1,58, 50, 42, 34, 26, 18, 10, 2,59, 51, 43, 35, 27, 19, 11, 3,60, 52, 44, 36, 63, 55, 47, 39,31, 23, 15, 7, 62, 54, 46, 38,30, 22, 14, 6, 61, 53, 45, 37,29, 21, 13, 5, 28, 20, 12, 4]
    PermChoice2 = [14, 17, 11, 24, 1, 5, 3, 28,15, 6, 21, 10, 23, 19, 12, 4,26, 8, 16, 7, 27, 20, 13, 2,41, 52, 31, 37, 47, 55, 30, 40,51, 45, 33, 48, 44, 49, 39, 56,34, 53, 46, 42, 50, 36, 29, 32]
    e_table = [32, 1, 2, 3, 4, 5,4, 5, 6, 7, 8, 9,8, 9, 10, 11, 12, 13,12, 13, 14, 15, 16, 17,16, 17, 18, 19, 20, 21,20, 21, 22, 23, 24, 25,24, 25, 26, 27, 28, 29,28, 29, 30, 31, 32, 1]

    # Function to XOR 2 strings of binary characters
    def xor_str(str1, str2):
        result = ""
        # For each bit add XOR value to the result string
        result = ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(str1, str2))
        return result

    # Function for S-box substitution and reduce 48-bit data to 32-bits
    def substitution(input_block):
        
        # Define the 8 S-boxes
        S_BOXES = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        ]
        
        # Empty list for output
        out = []
        
        # Splits 48 bits into 8 sets of 6 bits
        for i in range(8):
            # Extract a 6-bit block for current S-box
            block = input_block[i * 6:(i + 1) * 6]
            
            # Row is determined by 1st and last bit, row by the middle 4 bits
            row = int(block[0] + block[5], 2)
            col = int(''.join(block[1:5]), 2)
            
            # Get the value from the S-box
            sbox_value = S_BOXES[i][row][col]
            # Convert to 4-bit value
            sbox_binary = format(sbox_value, '04b')
            
            # Append the result to the output
            out.append(sbox_binary)
        
        # Retrun the list of values a string
        return ''.join(out)

    # Function to take a block of input and permutate it with one of the prespecified tables
    def permutate(block_in, Perm_Table):
        # Empty list for output permutations
        permutated = []

        # Loop through the permutation table and get the corresponding bits from block_in
        for position in Perm_Table:
            # Tables are in 10based index and python is on 0-based. Must subtract 1 from the position. 
            bit = int(block_in[position - 1])
            permutated.append(bit)

        # Convert the permutated list into string
        return ''.join(str(bit) for bit in permutated)

    # Generates a list of 16 subkeys based on input key
    def gen_subkey(key):
        subkeys = []

        # Remove pairity bits and permutate (PC1)
        key = permutate(key, Pairity_Remove)
        
        # Split into 2 halves
        C = key[:28]
        D = key[28:]

        # Make 16 keys
        for i in range(16):
            C, D = LShift(C, D, i)                          # Shift
            PermCH2 = permutate((C+D), PermChoice2)         # Permutate (PC2)
            subkeys.append(PermCH2)                         # Append value

        return subkeys

    # Function to shift C and D of the keys specified value based on round number
    def LShift(C, D, Roundnum):
        if Roundnum in (0,1,8,15):
            shift = 1
        else:
            shift = 2
        # Left circular shift by either 1 or 2 bits
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]

        return C, D

    # Encrypts the input using DES
    def Encrypt(plaintext, key):
        # Generates keyset for encryption based of input key
        keyset = gen_subkey(key)
        # Performs initial permutation of plaintext
        plaintext = permutate(plaintext, IPpermutation)
        
        #Breaks plaintext into left and right
        left = plaintext[:32]
        right = plaintext[32:]

        # Loop performs the Feistel structure: expand, xor, s-box, permutation
        for x in range(16):
            key = keyset[x]
            expanded = permutate(right, e_table)
            xord = xor_str(expanded, key)
            subd = substitution(xord)
            permd = permutate(subd, Fpermutation)

            #Does the Swap and XOR in one line
            left, right = right, xor_str(left, permd)

        # Performs final swap and permutation, returning ciphertext
        return permutate((right + left), FPpermutation)

    # Decrypts input using DES
    def Decrypt(ciphertext, key):
        # Generates keyset for encryption based of input key
        keyset = gen_subkey(key)
        # Performs initial permutation of ciphertext
        ciphertext = permutate(ciphertext, IPpermutation)

        # Reverses the swap performed at the end of the Encryption
        left = ciphertext[32:]
        right = ciphertext[:32]

        # Loop performs the Feistel structure: expand, xor, s-box, permutation. Does loop in reverse to match proper keys
        for x in range(16-1, -1, -1):
            key = keyset[x]
            expanded = permutate(left, e_table)
            xord = xor_str(expanded, key)
            subd = substitution(xord)
            permd = permutate(subd, Fpermutation)
            
            #Does the Swap and XOR in one line
            right, left = left, xor_str(right, permd)

        # Performs final permutation
        return permutate((left + right), FPpermutation)