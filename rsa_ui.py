from sympy import randprime, lcm, gcd, mod_inverse
from tkinter import ttk
import tkinter as tk
import pyperclip

def load_tab(frame):
    # Generate two large random prime numbers using sympy
    p = randprime(10**50, 10**51)
    q = randprime(10**50, 10**51)

    # Calculate modulus n
    n = p * q

    # Calculate Euler's totient
    phi_n = lcm(p - 1, q - 1)

    # Chose public exponent
    e = 65537
    assert gcd(e, phi_n) == 1, "e and phi_n are not coprime!"

    # Calculate d, multiplicative inverse of e
    d = mod_inverse(e, phi_n)

    # Dictionary of values to show and copy
    variables = {
        "Prime (p)": p,
        "Prime (q)": q,
        "Modulus (n)": n,
        "Euler's Totient (φ(n))": phi_n,
        "Public exponent (e)": e,
        "Private exponent (d)": d,
        "Public key (n, e)": f"({n}, {e})",
        "Private key (n, d)": f"({n}, {d})"

    }

    # Create a frame for layout
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
    
    # Configure resizing behavior
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(0, weight=1, uniform="equal")

    # Title
    title_label = ttk.Label(content_frame, text="RSA Key Generation", font=("Helvetica", 16, "bold"))
    title_label.grid(row=0, column=0, pady=(0, 15))

    # Output display (read-only text box)
    output_text = tk.Text(content_frame, wrap="word", height=25, width=70)
    output_text.grid(row=1, column=0, pady=10)
    output_text.insert("1.0", "\n\n".join(f"{k}: {v}" for k, v in variables.items()))
    output_text.config(state="disabled")  # Read-only

    # Frame for dropdown + button
    selection_frame = ttk.Frame(content_frame)
    selection_frame.grid(row=2, column=0, pady=10)

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
