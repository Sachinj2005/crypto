"""Saviour Vault desktop dashboard.

Keep this file beside the existing, working main.py.
Run: python gui.py
"""

import hashlib
import os
import secrets
import string
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from main import generate_key, MAGIC, SALT_SIZE, NONCE_SIZE, HEADER_SIZE


# Use exactly the same ACV1 format as main.py.
def read_encrypted(path):
    data = Path(path).read_bytes()
    if len(data) < HEADER_SIZE + 16 or data[:4] != MAGIC:
        raise ValueError("Not a valid Saviour Vault ACV1 encrypted file.")
    salt = data[4:4 + SALT_SIZE]
    nonce = data[4 + SALT_SIZE:HEADER_SIZE]
    return data, salt, nonce


def encrypt_file(path, password):
    source = Path(path)
    if len(password) < 12:
        raise ValueError("Please use at least 12 password characters.")
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    header = MAGIC + salt + nonce
    ciphertext = AESGCM(generate_key(password, salt)).encrypt(
        nonce, source.read_bytes(), header
    )
    output = Path(str(source) + ".enc")
    with output.open("xb") as target:
        target.write(header + ciphertext)
    return output


def authenticate_file(path, password):
    """Return plaintext only after the GCM tag passes verification."""
    source = Path(path)
    if not source.name.endswith(".enc"):
        raise ValueError("Choose a file ending in .enc.")
    data, salt, nonce = read_encrypted(source)
    try:
        return AESGCM(generate_key(password, salt)).decrypt(
            nonce, data[HEADER_SIZE:], data[:HEADER_SIZE]
        )
    except InvalidTag as exc:
        raise ValueError("Wrong password or encrypted file was modified.") from exc


def decrypt_file(path, password):
    plaintext = authenticate_file(path, password)
    source = Path(path)
    original = Path(source.name[:-4])
    output = source.with_name(original.stem + "_decrypted" + original.suffix)
    with output.open("xb") as target:
        target.write(plaintext)
    return output


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def make_password(length):
    if not 12 <= length <= 128:
        raise ValueError("Choose a password length between 12 and 128.")
    groups = [string.ascii_lowercase, string.ascii_uppercase,
              string.digits, "!@#$%^&*()-_=+?"]
    chars = [secrets.choice(group) for group in groups]
    chars += [secrets.choice("".join(groups)) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def inspect_file(path):
    source = Path(path)
    data, salt, nonce = read_encrypted(source)
    return (
        f"File: {source.name}\n"
        f"Format: ACV1\nAlgorithm: AES-256-GCM\n"
        f"KDF: Scrypt (N=16384, r=8, p=1)\n"
        f"Salt (16 bytes): {salt.hex()}\n"
        f"Nonce (12 bytes): {nonce.hex()}\n"
        f"Ciphertext + tag: {len(data) - HEADER_SIZE} bytes\n"
        f"Total size: {len(data)} bytes\n\n"
        "Inspection reads metadata only: it does NOT authenticate the file."
    )


class SaviourVault(tk.Tk):
    """Responsive dark desktop interface for the ACV1 file tools."""

    COLORS = {
        "window": "#0b1110",
        "surface": "#111a18",
        "raised": "#17221f",
        "input": "#0d1513",
        "border": "#263630",
        "green": "#21c78a",
        "green_hover": "#31dda0",
        "text": "#edf6f2",
        "muted": "#91a69d",
        "subtle": "#667a71",
        "danger": "#ff7b78",
        "success": "#55d6a1",
    }

    def __init__(self):
        super().__init__()
        self.title("Saviour Vault | Applied Cryptography")
        self.geometry("940x740")
        self.minsize(680, 580)
        self.configure(bg=self.COLORS["window"])

        self.mode = tk.StringVar(value="Encrypt")
        self.file = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.first_file = tk.StringVar()
        self.second_file = tk.StringVar()
        self.inspect_path = tk.StringVar()
        self.length = tk.StringVar(value="20")
        self.generated = tk.StringVar()
        self.status = tk.StringVar(value="Ready  ·  All operations run locally on this computer.")

        self._configure_styles()
        self._build_shell()

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        c = self.COLORS
        style.configure("TFrame", background=c["surface"])
        style.configure("TLabel", background=c["surface"], foreground=c["text"],
                        font=("Segoe UI", 10))
        style.configure("Muted.TLabel", foreground=c["muted"])
        style.configure("Section.TLabel", foreground=c["text"],
                        font=("Segoe UI Semibold", 17))
        style.configure("Field.TLabel", foreground=c["muted"],
                        font=("Segoe UI Semibold", 9))
        style.configure("TNotebook", background=c["window"], borderwidth=0,
                        tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=c["surface"], foreground=c["muted"],
                        padding=(17, 12), borderwidth=0,
                        font=("Segoe UI Semibold", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", c["raised"]), ("active", c["raised"])],
                  foreground=[("selected", c["green"]), ("active", c["text"])])
        style.configure("TEntry", fieldbackground=c["input"], foreground=c["text"],
                        insertcolor=c["text"], bordercolor=c["border"],
                        lightcolor=c["border"], darkcolor=c["border"],
                        padding=(11, 9), font=("Segoe UI", 10))
        style.map("TEntry", fieldbackground=[("readonly", c["input"])],
                  foreground=[("readonly", c["muted"])])
        style.configure("TButton", background=c["raised"], foreground=c["text"],
                        borderwidth=0, padding=(14, 9), font=("Segoe UI Semibold", 9))
        style.map("TButton", background=[("disabled", c["raised"]),
                                         ("pressed", c["border"]),
                                         ("active", "#20312b")],
                  foreground=[("disabled", c["subtle"])])
        style.configure("Accent.TButton", background=c["green"], foreground="#06130e",
                        padding=(16, 12), font=("Segoe UI Semibold", 10))
        style.map("Accent.TButton", background=[("disabled", "#366b57"),
                                                 ("pressed", "#17a975"),
                                                 ("active", c["green_hover"])])
        style.configure("TRadiobutton", background=c["raised"], foreground=c["muted"],
                        font=("Segoe UI Semibold", 9), padding=(12, 8))
        style.map("TRadiobutton", background=[("active", c["raised"])],
                  foreground=[("selected", c["green"]), ("active", c["text"])])
        style.configure("TCheckbutton", background=c["surface"], foreground=c["muted"],
                        font=("Segoe UI", 9), padding=(0, 4))
        style.map("TCheckbutton", background=[("active", c["surface"])],
                  foreground=[("active", c["text"])])
        style.configure("TSeparator", background=c["border"])

    def _build_shell(self):
        c = self.COLORS
        header = tk.Frame(self, bg=c["window"])
        header.pack(fill="x", padx=30, pady=(23, 17))

        brand = tk.Frame(header, bg=c["window"])
        brand.pack(side="left", fill="x", expand=True)
        tk.Label(brand, text="SV", bg=c["green"], fg="#07140f",
                 font=("Segoe UI Semibold", 13), width=3, height=1).pack(side="left", padx=(0, 13))
        title_area = tk.Frame(brand, bg=c["window"])
        title_area.pack(side="left", fill="x", expand=True)
        tk.Label(title_area, text="SAVIOUR VAULT", bg=c["window"], fg=c["text"],
                 font=("Segoe UI Semibold", 19)).pack(anchor="w")
        tk.Label(title_area, text="APPLIED CRYPTOGRAPHY  ·  AES-256-GCM  ·  SCRYPT  ·  SHA-256",
                 bg=c["window"], fg=c["muted"],
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        tk.Label(header, text="LOCAL & PRIVATE", bg=c["window"], fg=c["green"],
                 font=("Segoe UI Semibold", 8)).pack(side="right", anchor="n", pady=7)

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=25, pady=(0, 12))
        self.crypto_tab = self._panel(self.tabs)
        self.integrity_tab = self._panel(self.tabs)
        self.tools_tab = self._panel(self.tabs)
        self.about_tab = self._panel(self.tabs)
        self.tabs.add(self.crypto_tab, text="  File Security  ")
        self.tabs.add(self.integrity_tab, text="  Integrity Checker  ")
        self.tabs.add(self.tools_tab, text="  Security Tools  ")
        self.tabs.add(self.about_tab, text="  How It Works  ")
        self.build_crypto()
        self.build_integrity()
        self.build_tools()
        self.build_about()

        status_bar = tk.Frame(self, bg=c["surface"], height=38)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        self.status_label = tk.Label(status_bar, textvariable=self.status,
                                     bg=c["surface"], fg=c["muted"], anchor="w",
                                     font=("Segoe UI", 9))
        self.status_label.pack(fill="both", padx=29)

    def _panel(self, parent):
        return tk.Frame(parent, bg=self.COLORS["surface"], padx=24, pady=22)

    def _card(self, parent, padding=19):
        return tk.Frame(parent, bg=self.COLORS["raised"], padx=padding, pady=padding,
                        highlightthickness=1, highlightbackground=self.COLORS["border"])

    def title_line(self, parent, title, description):
        heading = ttk.Label(parent, text=title, style="Section.TLabel")
        heading.pack(anchor="w")
        detail = ttk.Label(parent, text=description, style="Muted.TLabel", wraplength=720)
        detail.pack(anchor="w", pady=(5, 17))

        def resize(event):
            detail.configure(wraplength=max(260, event.width - 8))
        parent.bind("<Configure>", resize, add="+")

    def _field_label(self, parent, text):
        ttk.Label(parent, text=text.upper(), style="Field.TLabel").pack(anchor="w", pady=(0, 6))

    def file_picker(self, parent, variable, encrypted=False):
        row = tk.Frame(parent, bg=parent.cget("bg"))
        row.pack(fill="x", pady=(0, 15))
        ttk.Entry(row, textvariable=variable, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(0, 9))

        def browse():
            types = ([('Encrypted files', '*.enc'), ('All files', '*.*')]
                     if encrypted else [('All files', '*.*')])
            name = filedialog.askopenfilename(filetypes=types)
            if name:
                variable.set(name)
        ttk.Button(row, text="Browse…", command=browse).pack(side="right")

    def build_crypto(self):
        tab = self.crypto_tab
        self.title_line(tab, "File Security", "Protect, recover or authenticate a file with your password.")
        card = self._card(tab)
        card.pack(fill="x", anchor="n")
        modes = tk.Frame(card, bg=self.COLORS["raised"])
        modes.pack(fill="x", pady=(0, 18))
        for label in ("Encrypt", "Decrypt", "Verify"):
            ttk.Radiobutton(modes, text=label, value=label, variable=self.mode,
                            command=self.update_crypto_mode).pack(side="left", padx=(0, 7))

        self._field_label(card, "File")
        self.file_picker(card, self.file)
        self._field_label(card, "Password")
        self.password_entry = ttk.Entry(card, textvariable=self.password, show="•")
        self.password_entry.pack(fill="x", pady=(0, 12))
        self.confirm_label = ttk.Label(card, text="CONFIRM PASSWORD", style="Field.TLabel")
        self.confirm_label.pack(anchor="w", pady=(0, 6))
        self.confirm_entry = ttk.Entry(card, textvariable=self.confirm, show="•")
        self.confirm_entry.pack(fill="x", pady=(0, 8))
        self.show_password_check = ttk.Checkbutton(
            card, text="Show password", variable=self.show_password,
            command=self.toggle_password)
        self.show_password_check.pack(anchor="w", pady=(0, 15))
        self.run_button = ttk.Button(card, text="Encrypt File", style="Accent.TButton",
                                     command=self.run_crypto)
        self.run_button.pack(fill="x")
        ttk.Label(tab, text="Encrypted output uses the existing ACV1 format. Verification checks the GCM tag and saves no plaintext.",
                  style="Muted.TLabel", wraplength=720).pack(anchor="w", pady=(14, 0))

    def toggle_password(self):
        mask = "" if self.show_password.get() else "•"
        self.password_entry.configure(show=mask)
        self.confirm_entry.configure(show=mask)

    def update_crypto_mode(self):
        operation = self.mode.get()
        self.run_button.configure(text=operation + " File")
        if operation == "Encrypt":
            self.confirm_label.pack(anchor="w", before=self.show_password_check, pady=(0, 6))
            self.confirm_entry.pack(fill="x", before=self.show_password_check, pady=(0, 8))
        else:
            self.confirm_label.pack_forget()
            self.confirm_entry.pack_forget()
        self.file.set("")
        self.password.set("")
        self.confirm.set("")

    def run_crypto(self):
        path, password = self.file.get(), self.password.get()
        if not path or not Path(path).is_file():
            messagebox.showerror("Missing file", "Choose an existing file first.")
            return
        if not password:
            messagebox.showerror("Missing password", "Enter a password first.")
            return
        if self.mode.get() == "Encrypt" and password != self.confirm.get():
            messagebox.showerror("Password mismatch", "Confirmation does not match.")
            return
        self.run_button.configure(state="disabled")
        self.set_status("Processing file…", "green")
        self.update_idletasks()
        try:
            if self.mode.get() == "Encrypt":
                result = encrypt_file(path, password)
                message = f"Encrypted file saved:\n{result}"
            elif self.mode.get() == "Decrypt":
                result = decrypt_file(path, password)
                message = f"Recovered file saved:\n{result}"
            else:
                authenticate_file(path, password)
                message = "Authentication passed. No decrypted file was saved."
            self.set_status(self.mode.get() + " completed successfully.", "success")
            messagebox.showinfo("Saviour Vault", message)
        except (OSError, ValueError) as exc:
            self.set_status("Operation failed: " + str(exc), "error")
            messagebox.showerror("Unable to complete", str(exc))
        finally:
            self.password.set("")
            self.confirm.set("")
            self.run_button.configure(state="normal")

    def output(self, parent, height=8):
        widget = tk.Text(parent, height=height, wrap="word", bg=self.COLORS["input"],
                         fg=self.COLORS["text"], insertbackground=self.COLORS["text"],
                         selectbackground="#236449", relief="flat", borderwidth=0,
                         font=("Cascadia Mono", 9), padx=13, pady=12,
                         highlightthickness=1, highlightbackground=self.COLORS["border"])
        widget.pack(fill="both", expand=True, pady=(10, 0))
        widget.configure(state="disabled")
        return widget

    @staticmethod
    def write_output(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

    def build_integrity(self):
        tab = self.integrity_tab
        self.title_line(tab, "Integrity Checker", "Create SHA-256 fingerprints or compare two files for an exact content match.")
        card = self._card(tab)
        card.pack(fill="x")
        self._field_label(card, "First file")
        self.file_picker(card, self.first_file)
        self._field_label(card, "Second file · optional for a single hash")
        self.file_picker(card, self.second_file)
        buttons = tk.Frame(card, bg=self.COLORS["raised"])
        buttons.pack(fill="x", pady=(0, 2))
        ttk.Button(buttons, text="Calculate SHA-256", style="Accent.TButton",
                   command=self.run_hash).pack(side="left", padx=(0, 9))
        ttk.Button(buttons, text="Compare files", command=self.run_compare).pack(side="left")
        self.hash_output = self.output(tab, 7)

    def run_hash(self):
        try:
            result = sha256_file(self.first_file.get())
            self.write_output(self.hash_output,
                              f"SHA-256\n{result}\n\nFile: {self.first_file.get()}")
            self.set_status("SHA-256 fingerprint calculated.", "success")
        except (OSError, ValueError) as exc:
            self.set_status("Hash failed: " + str(exc), "error")
            messagebox.showerror("Hash failed", str(exc))

    def run_compare(self):
        try:
            a = sha256_file(self.first_file.get())
            b = sha256_file(self.second_file.get())
            result = "MATCH · same SHA-256 hash" if a == b else "DIFFERENT · hashes do not match"
            self.write_output(self.hash_output,
                              f"RESULT: {result}\n\nFirst:  {a}\nSecond: {b}")
            self.set_status("File comparison complete.", "success" if a == b else "error")
        except (OSError, ValueError) as exc:
            self.set_status("Comparison failed: " + str(exc), "error")
            messagebox.showerror("Comparison failed", str(exc))

    def build_tools(self):
        tab = self.tools_tab
        self.title_line(tab, "Security Tools", "Generate a strong password or inspect ACV1 metadata without authenticating a file.")
        generator = self._card(tab)
        generator.pack(fill="x", pady=(0, 14))
        ttk.Label(generator, text="Password Generator", style="Section.TLabel").pack(anchor="w")
        ttk.Label(generator, text="Uses Python’s cryptographically secure secrets module.",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 14))
        row = tk.Frame(generator, bg=self.COLORS["raised"])
        row.pack(fill="x")
        ttk.Label(row, text="Length (12–128)", style="Field.TLabel").pack(side="left", padx=(0, 10))
        ttk.Entry(row, width=8, textvariable=self.length).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Generate password", style="Accent.TButton",
                   command=self.run_password).pack(side="left")
        ttk.Entry(generator, textvariable=self.generated, state="readonly").pack(
            fill="x", pady=(13, 0))

        inspector = self._card(tab)
        inspector.pack(fill="both", expand=True)
        ttk.Label(inspector, text="Encrypted File Inspector", style="Section.TLabel").pack(anchor="w")
        ttk.Label(inspector, text="Displays format, salt and nonce. Inspection does not prove authenticity.",
                  style="Muted.TLabel", wraplength=700).pack(anchor="w", pady=(4, 12))
        self.file_picker(inspector, self.inspect_path, encrypted=True)
        ttk.Button(inspector, text="Inspect file", command=self.run_inspect).pack(anchor="w")
        self.inspect_output = self.output(inspector, 6)

    def run_password(self):
        try:
            self.generated.set(make_password(int(self.length.get())))
            self.set_status("New password generated locally. Keep it private.", "success")
        except ValueError:
            messagebox.showerror("Invalid length", "Enter a number from 12 to 128.")

    def run_inspect(self):
        try:
            self.write_output(self.inspect_output, inspect_file(self.inspect_path.get()))
            self.set_status("Encrypted file metadata loaded. Authentication was not checked.")
        except (OSError, ValueError) as exc:
            self.set_status("Inspection failed: " + str(exc), "error")
            messagebox.showerror("Inspection failed", str(exc))

    def build_about(self):
        tab = self.about_tab
        self.title_line(tab, "How It Works", "A concise overview of the cryptographic workflow used by Saviour Vault.")
        card = self._card(tab)
        card.pack(fill="both", expand=True)
        steps = [
            ("01", "Choose a file and enter a password.", "Encryption requires a confirmation before it starts."),
            ("02", "Derive a key with Scrypt.", "A random salt and Scrypt produce a 256-bit key from the password."),
            ("03", "Encrypt with AES-256-GCM.", "A unique 12-byte nonce protects the file and GCM provides authentication."),
            ("04", "Store the existing ACV1 format.", "The format contains its marker, salt, nonce, ciphertext and authentication tag."),
            ("05", "Authenticate before recovery.", "Decryption verifies the tag before writing plaintext; Verify checks without saving it."),
            ("06", "Check integrity with SHA-256.", "Compare fingerprints of the original and recovered files."),
        ]
        for number, heading, detail in steps:
            row = tk.Frame(card, bg=self.COLORS["raised"])
            row.pack(fill="x", pady=(0, 15))
            tk.Label(row, text=number, bg=self.COLORS["input"], fg=self.COLORS["green"],
                     font=("Segoe UI Semibold", 9), padx=10, pady=7).pack(side="left", anchor="n", padx=(0, 12))
            copy = tk.Frame(row, bg=self.COLORS["raised"])
            copy.pack(side="left", fill="x", expand=True)
            tk.Label(copy, text=heading, bg=self.COLORS["raised"], fg=self.COLORS["text"],
                     font=("Segoe UI Semibold", 10), anchor="w").pack(fill="x")
            tk.Label(copy, text=detail, bg=self.COLORS["raised"], fg=self.COLORS["muted"],
                     font=("Segoe UI", 9), anchor="w", justify="left", wraplength=680).pack(fill="x", pady=(3, 0))
        ttk.Separator(card).pack(fill="x", pady=(0, 12))
        ttk.Label(card, text="Demo note: intended for small local files. The original plaintext remains on disk after encryption.",
                  style="Muted.TLabel", wraplength=700).pack(anchor="w")

    def set_status(self, message, tone="default"):
        colors = {"default": self.COLORS["muted"], "green": self.COLORS["green"],
                  "success": self.COLORS["success"], "error": self.COLORS["danger"]}
        self.status.set(message)
        self.status_label.configure(fg=colors.get(tone, self.COLORS["muted"]))


if __name__ == "__main__":
    SaviourVault().mainloop()
