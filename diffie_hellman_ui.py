from tkinter import ttk
import tkinter as tk
import pyperclip
from sympy import randprime
import random

def load_tab(frame):
    # Generate a large prime number that 
    p = randprime(10**50, 10**51)

    # Decide on a random generator number
    g = 2

    # Make a private key randomly for each party
    a = random.randint(2, p - 2)  # Private key for a
    b = random.randint(2, p - 2)  # Private key for b

    # Determine the public key for each private key
    # Accepts base g and exponent a with modulus p - this determines the public key for each.
    A = pow(g, a, p)    # (g^a mod p)  
    B = pow(g, b, p)    # (g^b mod p) 

    # Compute shared secret
    AS = pow(B, a, p)  # (B^a mod p)
    BS = pow(A, b, p)    # (A^b mod p)

    if AS == BS:
        var = "YES"
    else:
        var = "NO"

    # Dictionary of values to show and copy
    variables = {
        "Prime (p)": p,
        "Generator (g)": g,
        "A's Private Key (a)": a,
        "B's Private Key (b)": b,
        "A's Public Key (A)": A,
        "B's Public Key (B)": B,
        "A's Shared Secret (AS)": AS,
        "B's Shared Secret (BS)": BS,
        "Shared Secret Matches?": var,
    }

    # Create a frame for layout
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
    
    # Configure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")

    # Title
    title_label = ttk.Label(content_frame, text="Diffie Hellman Key Exchange", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))

    # Output display (read-only text box)
    output_text = tk.Text(content_frame, wrap="word", height=25, width=70)
    output_text.grid(row=1, column=0, pady=(5, 2))
    output_text.insert("1.0", "\n\n".join(f"{k}: {v}" for k, v in variables.items()))
    output_text.config(state="disabled")  # Read-only

    # Frame for dropdown + button
    selection_frame = ttk.Frame(content_frame)
    selection_frame.grid(row=2, column=0, pady=(5,2))

    # Dropdown list
    variable_names = list(variables.keys())
    selected_var = tk.StringVar(value=variable_names[0])
    dropdown = ttk.Combobox(selection_frame, textvariable=selected_var, values=variable_names, state="readonly", width=30)
    dropdown.grid(row=0, column=0, padx=5)

    # Copy button
    def copy_to_clipboard():
        value = variables.get(selected_var.get(), "")
        pyperclip.copy(str(value))

    copy_button = ttk.Button(selection_frame, text="Copy", command=copy_to_clipboard)
    copy_button.grid(row=0, column=1, padx=5)

    # Ensure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)




    
        