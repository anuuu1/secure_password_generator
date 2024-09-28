import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

class PasswordManager:
    def __init__(self, master):
        self.master=master
        self.master.title(" Secure Password Generator")
        self.master.geometry("400x500")

        self.notebook= ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.generator_frame=ttk.Frame(self.notebook)
        self.manager_frame= ttk.Frame(self.notebook)

        self.notebook.add(self.generator_frame, text="Generator")

        self.setup_generator()

    def setup_generator(self):
            self.length_var=tk.StringVar(value="12")
            self.uppercase_var=tk.BooleanVar(value=True)
            self.lowercase_var=tk.BooleanVar(value=True)
            self.numbers_var=tk.BooleanVar(value=True)
            self.symbols_var=tk.BooleanVar(value=True)
            self.password_var=tk.StringVar()

            ttk.Label(self.generator_frame, text="Password Length:").pack(pady=5)
            ttk.Entry(self.generator_frame, textvariable=self.length_var, width=5).pack()

            ttk.Checkbutton(self.generator_frame, text="Uppercase", variable=self.uppercase_var).pack()
            ttk.Checkbutton(self.generator_frame, text="Lowercase", variable=self.lowercase_var).pack()
            ttk.Checkbutton(self.generator_frame, text="Numbers", variable=self.numbers_var).pack()
            ttk.Checkbutton(self.generator_frame, text="Symbols", variable=self.symbols_var).pack()

            ttk.Button(self.generator_frame,text="Generate Password", command=self.generate_password).pack(pady=10)
            ttk.Entry(self.generator_frame, textvariable=self.password_var, state="readonly", width=30).pack()
            ttk.Button(self.generator_frame,text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=10)


    def generate_password(self):

                length = int(self.length_var.get())
                characters=""
                if self.uppercase_var.get():
                    characters +=string.ascii_uppercase
                if self.lowercase_var.get():
                    characters += string.ascii_lowercase
                if self.numbers_var.get():
                    characters += string.digits
                if self.symbols_var.get():
                    characters += string.punctuation

                if not characters:
                    self.password_var.set("Please select at least one character type")
                else:
                    password=''.join(random.choice(characters) for _ in range(length))
                    self.password_var.set(password)

    def copy_to_clipboard(self):
                 password = self.password_var.get()
                 if password:
                      self.master.clipboard_clear()
                      self.master.clipboard_append(password)
                      messagebox.showinfo("Copied", "Password copied to clipboard!")
                 else:
                    messagebox.showwarning("No Password", "Generate a password first.")


if __name__ == "__main__":
    root=tk.Tk()
    app= PasswordManager(root)
    root.mainloop()
