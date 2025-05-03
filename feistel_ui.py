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
    title_label = ttk.Label(content_frame, text="Feistel Cipher Tool", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))

    # Label for the numerical key
    label = ttk.Label(content_frame, text="Enter 16 character key:")
    label.grid(row=1, column=0, pady=(5, 2))  # Reduced the vertical padding here
    key_input = ttk.Entry(content_frame, width=30)
    key_input.grid(row=2, column=0, pady=(0,10))

    # Label and Text input for the message
    label2 = ttk.Label(content_frame, text="Enter message:")
    label2.grid(row=3, column=0, pady=(5, 2))  # Reduced the vertical padding here too
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
        plaintext = message_input.get("1.0", tk.END).strip()
        plaintext = plaintext.encode('utf-8')
        
        #Turns data into blocks 16 chars or 128 bits long
        blocks = []        
        for i in range(0, len(plaintext), 16):
            blocks.append(plaintext[i:i+16])

        #Pads the last block if not 16 chars long
        if len(blocks[-1]) < 16:
            last = blocks[-1]
            last_chunk = last + b'*' * (16 - len(last))
            blocks[-1] = last_chunk


        #Sets the encryption/decryption key
        key = key_input.get().strip()
        key = key.encode('utf-8')

        #Sets first key in keyset to the one listed above
        keys = [key]

        #Perform 2 char left circular shift
        for _ in range(len(blocks) -1):
            key = key[2:] + key[:2]
            keys.append(key)
        
        #Specifies the number of rounds
        rounds = 16

        mout = []

        #Loop to encrypt and decrypt each block with a different key from the keyset
        for block, key in zip(blocks, keys):
            ciphertext = Encrypt(block, key, rounds)
            mout.append(ciphertext.hex())
        result = ''.join(mout)
        # Convert the binary string back to characters
        output_label.config(text=result)
        return result


    def ondecrypt():
        #Sets the encryption/decryption key
        
        ciphertext = message_input.get("1.0", tk.END).strip()

        inblocks = []        
        for i in range(0, len(ciphertext), 32):
            inblocks.append(ciphertext[i:i+32])
        
        blocks = []
        for ciphertext in inblocks:
            hexed = bytes.fromhex(ciphertext)
            blocks.append(hexed)

        key = key_input.get().strip()
        key = key.encode('utf-8')

        #Sets first key in keyset to the one listed above
        keys = [key]

        #Perform 2 char left circular shift
        for _ in range(len(blocks) -1):
            key = key[2:] + key[:2]
            keys.append(key)

        mout = []

        #Loop to encrypt and decrypt each block with a different key from the keyset
        for block, key in zip(blocks, keys):
            plaintext = Decrypt(block, key, 16)
            #Removes * padding from last block
            while plaintext.endswith(b'*'):
                plaintext = plaintext[:-1]
            mout.append(plaintext)

        result = ''.join([pt.decode('utf-8', errors='ignore') for pt in mout])
        # Convert the binary string back to characters
        output_label.config(text=result)
        return result



    #Function to xor two byte strings
    def xor_str(str1, str2):
        result = b""
        #For each bit in the zipped str1, str2 pair, add the XOR value to the result string
        for b1, b2 in zip(str1, str2):
            result += bytes([b1 ^ b2])
        return result

    #Function to perform substitution
    def sub(data_in):
        #Bijective S-Box: removes need for inverse S-Box as x:y and y:x
        S_box = {
            0x0: 0x6, 0x1: 0x7, 0x2: 0xC, 0x3: 0x3,
            0x4: 0x9, 0x5: 0xF, 0x6: 0x0, 0x7: 0x1,
            0x8: 0xD, 0x9: 0x4, 0xA: 0xB, 0xB: 0xA,
            0xC: 0x2, 0xD: 0x8, 0xE: 0xE, 0xF: 0x5
        }
        
        #Creates an empty list for the substituted "nibble," which is half a byte or enough to represent all hexadecimal characters
        sub_block = []
        for byte in data_in:
            #Split byte in half
                #Sets upper
            upper = (byte >> 4) & 0xF
                #Sets lower
            lower = byte & 0xF

            #Substitute each value using above S-box
            sub_upper = S_box.get(upper, upper)
            sub_lower = S_box.get(lower, lower)

            #Put the byte back together 
            sub_byte = (sub_upper << 4) | sub_lower
            sub_block.append(sub_byte)

        return bytes(sub_block)

    #Performs the permutation for the feistel cipher
    def permutate(data_in):
        #Create empty result
        result = []
        #Loop for each input byte
        for byte in data_in:
            #Create result byte
            new_byte = 0
            #Loop incrementing by 2 to swap every two bits in a byte. In abcdefgh, it becomes badcfehg, which is a simple permutation
            for x in range(0, 8, 2):
                #Get and swap the pair of bits
                bit_pair = ((byte >> x) & 3)
                swapped_pair = ((bit_pair >> 1) & 1) | ((bit_pair & 1) << 1)  # Swap the bits
                new_byte |= (swapped_pair << x)
            
            # Append the swapped byte to the result list
            result.append(new_byte)

        return bytes(result)

    #Function to Encrypt using the Feistel Cipher
    def Encrypt(plaintext, key, rounds):
        #Breaks the block of plaintext in half: left and right
        left = plaintext[:8]
        right = plaintext[8:]

        #Loop performs the F function and XOR
        for x in range(rounds):
            #Performs XOR of right side and key
            xor_strd = xor_str(right, key)
            #Performs substitution on results above
            subd = sub(xor_strd)       
            #Does permutation on above results
            permd = permutate(subd)

            #Does the Swap and XOR in one line
            left, right = right, xor_str(left, permd)

        #By putting right first, we perfom the final swap of the Feistel Cipher
        return right + left

    #Function to Decrypt using the Feistel Cipher
    def Decrypt(ciphertext, key, rounds):
        #Reverses the swap performed at the end of the Encryption
        right = ciphertext[:8]
        left = ciphertext[8:]

        for x in range(rounds):
            #Performs XOR of right side and key
            xor_strd = xor_str(left, key)        
            #Performs substitution on results above
            subd = sub(xor_strd)        
            #Does permutation on above results
            permd = permutate(subd)
            
            #Does the Swap and XOR in one line
            right, left = left, xor_str(right, permd)

        #No swap is performed here
        return left + right

