import os
import random
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, UTC

class KeyCertGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Key & Certificate Generator")
        self.root.geometry("500x500")
        
        self.fields = {
            "Name": "John Doe",
            "Organization": "ExampleCorp",
            "Country Code": "US",
            "State": "California",
            "City": "San Francisco",
            "Common Name (e.g., domain.com)": "example.com"
        }
        
        self.entries = {}
        for label, placeholder in self.fields.items():
            frame = tk.Frame(root)
            frame.pack(pady=5, fill='x')
            tk.Label(frame, text=label).pack(anchor='w')
            entry = tk.Entry(frame)
            entry.pack(fill='x')
            entry.insert(0, placeholder)
            self.entries[label] = entry
        
        self.generate_button = tk.Button(root, text="Generate Keys & Certificate", command=self.start_entropy)
        self.generate_button.pack(pady=20)
    
    def start_entropy(self):
        self.user_data = {label: entry.get() for label, entry in self.entries.items()}
        
        self.entropy_window = tk.Toplevel(self.root)
        self.entropy_window.geometry("400x300")
        self.entropy_window.title("Move Your Mouse!")
        tk.Label(self.entropy_window, text="Move your mouse randomly to generate entropy!", font=("Arial", 12)).pack(pady=10)
        
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(self.entropy_window, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.pack(pady=20)
        
        self.entropy = []
        self.target_moves = 200
        self.entropy_window.bind('<Motion>', self.collect_entropy)
    
    def collect_entropy(self, event):
        if len(self.entropy) < self.target_moves:
            self.entropy.append((event.x, event.y))
            self.progress_var.set(int((len(self.entropy) / self.target_moves) * 100))
            self.progress_bar.update_idletasks()
        
        if len(self.entropy) >= self.target_moves:
            self.entropy_window.destroy()
            self.generate_keys()
    
    def generate_keys(self):
        random.seed(sum(x + y for x, y in self.entropy))
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        self.generate_certificate(private_key)
    
    def generate_certificate(self, private_key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.user_data["Country Code"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.user_data["State"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.user_data["City"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.user_data["Organization"]),
            x509.NameAttribute(NameOID.COMMON_NAME, self.user_data["Common Name (e.g., domain.com)"]),
        ])
        
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        
        with open("certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        messagebox.showinfo("Success", "Key pair and self-signed certificate generated successfully!")
        
if __name__ == "__main__":
    root = tk.Tk()
    app = KeyCertGenerator(root)
    root.mainloop()