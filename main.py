import os
import random
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, UTC

class KeyCertManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Key & Certificate Manager")
        self.root.geometry("500x700")
        
        self.fields = {
            "Name": "John Doe",
            "Organization": "ExampleCorp",
            "Country Code": "US",
            "State": "California",
            "City": "San Francisco",
            "Common Name (e.g., domain.com)": "example.com",
            "Alias": "mykey",
            "Key Algorithm": "RSA",
            "Key Size": "2048",
            "Keystore Name": "mykeystore.jks",
            "Validity (days)": "365"
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
        self.generate_button.pack(pady=10)
        
        self.export_button = tk.Button(root, text="Export Certificate", command=self.export_certificate)
        self.export_button.pack(pady=10)
        
        self.import_button = tk.Button(root, text="Import Certificate", command=self.import_certificate)
        self.import_button.pack(pady=10)
        
        self.delete_button = tk.Button(root, text="Delete Keys & Certificate", command=self.delete_keys)
        self.delete_button.pack(pady=10)
    
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
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=int(self.user_data["Key Size"]))
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
            .not_valid_after(datetime.now(UTC) + timedelta(days=int(self.user_data["Validity (days)"])))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        
        with open("certificate.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        messagebox.showinfo("Success", f"Key pair and certificate generated successfully!\n\n-alias {self.user_data['Alias']}: Name of the key\n\n-keyalg {self.user_data['Key Algorithm']}: Algorithm used\n\n-keysize {self.user_data['Key Size']}: Key size\n\n-keystore {self.user_data['Keystore Name']}: Name of the keystore\n\n-validity {self.user_data['Validity (days)']}: Valid for {self.user_data['Validity (days)']} days")
    
    def export_certificate(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if filepath:
            with open("certificate.pem", "rb") as src, open(filepath, "wb") as dest:
                dest.write(src.read())
            messagebox.showinfo("Export", "Certificate exported successfully!")
    
    def import_certificate(self):
        filepath = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if filepath:
            with open(filepath, "rb") as src, open("imported_certificate.pem", "wb") as dest:
                dest.write(src.read())
            messagebox.showinfo("Import", "Certificate imported successfully!")
    
    def delete_keys(self):
        if messagebox.askyesno("Delete", "Are you sure you want to delete the generated keys and certificate?"):
            for file in ["private_key.pem", "public_key.pem", "certificate.pem", "imported_certificate.pem"]:
                if os.path.exists(file):
                    os.remove(file)
            messagebox.showinfo("Delete", "Keys and certificates deleted successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyCertManager(root)
    root.mainloop()