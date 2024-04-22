import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def cifrar_archivo():
    nombre_archivo = input("Ingrese el nombre del archivo a cifrar: ")
    try:
        with open(nombre_archivo, "rb") as file:
            contenido = file.read()
            backend = default_backend()
            key = os.urandom(24)
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
            contenido_padded = padder.update(contenido) + padder.finalize()
            contenido_cifrado = encryptor.update(contenido_padded) + encryptor.finalize()
            with open(nombre_archivo + "_cifrado.des", "wb") as file_cifrado:
                file_cifrado.write(contenido_cifrado)
            contenido_cifrado_base64 = base64.b64encode(contenido_cifrado)
            with open(nombre_archivo + "_cifrado.des_base64.txt", "wb") as file_cifrado_base64:
                file_cifrado_base64.write(contenido_cifrado_base64)
        print("Archivo cifrado y guardado como", nombre_archivo + "_cifrado.des y", nombre_archivo + "_cifrado.des_base64.txt")
        return key
    except FileNotFoundError:
        print("Archivo no encontrado")

def descifrar_archivo(key):
    nombre_archivo = input("Ingrese el nombre del archivo a descifrar: ")
    try:
        with open(nombre_archivo, "rb") as file:
            contenido_cifrado = file.read()
            backend = default_backend()
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()
            contenido_descifrado_padded = decryptor.update(contenido_cifrado) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
            contenido_descifrado = unpadder.update(contenido_descifrado_padded) + unpadder.finalize()
        with open(nombre_archivo[:-4] + "_descifrado.txt", "wb") as file_descifrado:
            file_descifrado.write(contenido_descifrado)
        print("Archivo descifrado y guardado como", nombre_archivo[:-4] + "_descifrado.txt")
    except FileNotFoundError:
        print("Archivo no encontrado")

llave = cifrar_archivo()
descifrar_archivo(llave)


while True:
    print("\nMenú:")
    print("1. Cifrar archivo")
    print("2. Descifrar archivo")
    print("3. Salir")
    opcion = input("Seleccione una opción: ")

    if opcion == "1":
        cifrar_archivo()
    elif opcion == "2":
        descifrar_archivo()
    elif opcion == "3":
        break
    else:
        print("Opción no válida. Intente de nuevo.")
