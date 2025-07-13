from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_keys():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

if __name__ == "__main__":
    priv, pub = generate_keys()

    # Print escaped output for .env usage
    print("PRIVATE_KEY=" + priv.replace('\n', '\\n'))
    print("PUBLIC_KEY=" + pub.replace('\n', '\\n'))

    # Optional: also save to local PEM files
    with open("private_key.pem", "w") as f:
        f.write(priv)

    with open("public_key.pem", "w") as f:
        f.write(pub)
