import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Task 1: Generate SHA-256 Hash [cite: 8]
def generate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# Task 2: Manifest Generator [cite: 9]
def generate_manifest(directory):
    manifest = {}
    for filename in os.listdir(directory):
        if os.path.isfile(os.path.join(directory, filename)) and filename != "metadata.json":
            manifest[filename] = generate_hash(os.path.join(directory, filename))
    with open("metadata.json", "w") as f:
        json.dump(manifest, f, indent=4)
    print("Metadata.json created successfully.")

# Task 4: Generate RSA Keys [cite: 12]
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Task 5: Signing the Manifest [cite: 13]
def sign_manifest(private_key):
    with open("metadata.json", "rb") as f:
        data = f.read()
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("Manifest signed successfully.")

# Task 6: Verification [cite: 14]
def verify_signature(public_key):
    try:
        with open("metadata.json", "rb") as f:
            data = f.read()
        with open("signature.sig", "rb") as f:
            signature = f.read()
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Verification Successful: Manifest is authentic.")
    except Exception:
        print("Verification Failed: Manifest altered or wrong sender!")

if __name__ == "__main__":
    priv, pub = generate_keys()
    generate_manifest(".") 
    sign_manifest(priv)
    verify_signature(pub)