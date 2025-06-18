import random
import string
import tkinter as tk
from tkinter import messagebox

def generate_password(length, use_upper, use_lower, use_digits, use_special):
    characters = ''
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return "Select at least one character set!"

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def on_generate():
    try:
        length = int(length_entry.get())
        if length <= 0:
            raise ValueError
    except ValueError:
        messagebox.showerror("Invalid input", "Password length must be a positive integer.")
        return

    password = generate_password(
        length,
        upper_var.get(),
        lower_var.get(),
        digits_var.get(),
        special_var.get()
    )
    result_var.set(password)

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_var.get())
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# GUI Setup
root = tk.Tk()
root.title("Password Generator")
root.geometry("400x300")

# Widgets
tk.Label(root, text="Password Length:").pack()
length_entry = tk.Entry(root)
length_entry.pack()

upper_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include Uppercase Letters", variable=upper_var).pack()

lower_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include Lowercase Letters", variable=lower_var).pack()

digits_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include Numbers", variable=digits_var).pack()

special_var = tk.BooleanVar()
tk.Checkbutton(root, text="Include Special Characters", variable=special_var).pack()

tk.Button(root, text="Generate Password", command=on_generate).pack(pady=10)

result_var = tk.StringVar()
tk.Entry(root, textvariable=result_var, width=40).pack()

tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=5)

root.mainloop()