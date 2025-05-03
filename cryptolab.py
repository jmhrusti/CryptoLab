# Import Tkinter for GUI and Theames for custom dark mode
# Import other modules for the different ciphers and encryption algorithms
from ttkthemes import ThemedTk
from tkinter import ttk
import block_modes_ui, caesar_ui, des_ui, diffie_hellman_ui, feistel_ui, hill_ui, monoalphabetic_ui, playfair_ui, rsa_ui, vernam_ui, vigenere_ui

# Use ThemedTk with Equilux
root = ThemedTk(theme="equilux")
root.title("CryptoLab")
root.state("zoomed")
root.configure(bg="#2e2e2e")

# Style configuration
style = ttk.Style(root)
style.configure("TNotebook", background="#2e2e2e")
style.configure("TNotebook.Tab", background="#444", foreground="#eee", padding=10)
style.map("TNotebook.Tab", background=[("selected", "#333")], foreground=[("selected", "#fff")])
style.configure("TFrame", background="#2e2e2e")
style.configure("TLabel", background="#2e2e2e", foreground="#ffffff")
style.configure("TButton", background="#444", foreground="#ffffff")

# Notebook setup
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both', padx=10, pady=10)

# Tabs setup
tab_home = ttk.Frame(notebook)
tab_block = ttk.Frame(notebook)
tab_caesar = ttk.Frame(notebook)
tab_des = ttk.Frame(notebook)
tab_diffie = ttk.Frame(notebook)
tab_feistel = ttk.Frame(notebook)
tab_hill = ttk.Frame(notebook)
tab_mono = ttk.Frame(notebook)
tab_playfair = ttk.Frame(notebook)
tab_rsa = ttk.Frame(notebook)
tab_vernam = ttk.Frame(notebook)
tab_vigenere = ttk.Frame(notebook)
tab_about = ttk.Frame(notebook)

# Add tabs to notebook
notebook.add(tab_home, text="Home")
notebook.add(tab_block, text="Block")
notebook.add(tab_caesar, text="Caesar")
notebook.add(tab_des, text="DES")
notebook.add(tab_diffie, text="Diffie Hellman")
notebook.add(tab_feistel, text="Feistel")
notebook.add(tab_hill, text="Hill")
notebook.add(tab_mono, text="Monoalphabetic")
notebook.add(tab_playfair, text="Playfair")
notebook.add(tab_rsa, text="RSA")
notebook.add(tab_vernam, text="Vernam")
notebook.add(tab_vigenere, text="Vigenère")
notebook.add(tab_about, text="About")


# Home tab content
home_label = ttk.Label(tab_home, text="Welcome to CryptoLab!", font=("Arial", 16))
home_label.pack(pady=20)

info_label = ttk.Label(
    tab_home,
    text="Choose a cipher tab above to begin experimenting with cipher and encryption techniques.",
    justify="center",
    font=("Arial", 11),
    wraplength=400
)
info_label.pack(pady=10)

# Button to navigate to about tab
def go_to_about():
    notebook.select(tab_about)

# Button to go to about
about_button = ttk.Button(tab_home, text="About", command=go_to_about)
about_button.pack(pady=15)

# About tab contents
about_label = ttk.Label(tab_about, text="About CryptoLab", font=("Arial", 16))
about_label.pack(pady=20)

about_text = ttk.Label(
    tab_about,
    text="CryptoLab is an educational toolkit for exploring classic encryption techniques.\n\nCreated by John Hrustich, Christopher Rawlins, and Kate Vaughan for CSC 432.\n\nVersion 1.0\n\nCopyright 2025",
    font=("Arial", 11),
    justify="center",
    wraplength=400
)
about_text.pack(pady=10)

# Load the UIs for all other ciphers
ui_tab_pairs = [
    (caesar_ui, tab_caesar),
    (diffie_hellman_ui, tab_diffie),
    (block_modes_ui, tab_block),
    (des_ui, tab_des),
    (feistel_ui, tab_feistel),
    (hill_ui, tab_hill),
    (monoalphabetic_ui, tab_mono),
    (playfair_ui, tab_playfair),
    (rsa_ui, tab_rsa),
    (vernam_ui, tab_vernam),
    (vigenere_ui, tab_vigenere)
]

# Call load_tab() for each cipher in list
for ui, tab in ui_tab_pairs:
    ui.load_tab(tab)

# Spawn window
root.mainloop()
