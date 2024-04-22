import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Generar la llave
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# Generar una contraseña aleatoria de 24 bytes (192 bits) para 3DES
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=24,
    salt=b'salt_3des',
    iterations=100000,
    backend=backend
)

key = kdf.derive(b"password")
print("Llave generada:", key)

# Transformar la llave a base64
key_base64 = base64.b64encode(key)
print("Llave en base64:", key_base64.decode())

# Almacenar la llave en un archivo de texto
with open("llave_3des.txt", "wb") as file:
    file.write(key_base64)
    print("Llave guardada en 'llave_3desImported.txt'")
