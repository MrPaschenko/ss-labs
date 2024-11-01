from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key


def client_hello():
    random_data = b"random_client_data"
    return random_data


def server_hello(public_key):
    random_data = b"random_server_data"
    certificate = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return random_data, certificate


def encrypt_premaster_secret(premaster_secret, server_public_key):
    ciphertext = server_public_key.encrypt(
        premaster_secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_premaster_secret(ciphertext, private_key):
    premaster_secret = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return premaster_secret


def generate_session_keys(client_random, server_random, premaster_secret):
    combined_data = client_random + server_random + premaster_secret

    cipher_key = hmac.HMAC(combined_data, hashes.SHA256(), backend=default_backend())
    cipher_key = cipher_key.finalize()

    auth_key = hmac.HMAC(combined_data, hashes.SHA256(), backend=default_backend())
    auth_key = auth_key.finalize()

    return cipher_key, auth_key


def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    return message


def client_ready_message(session_cipher_key):
    message = b"Ready from client"
    encrypted_message = encrypt_message(message, session_cipher_key)
    return encrypted_message


def server_ready_message(session_cipher_key):
    message = b"Ready from server"
    encrypted_message = encrypt_message(message, session_cipher_key)
    return encrypted_message


def secure_symmetric_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


def secure_symmetric_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


def client_send_message(message, session_cipher_key):
    encrypted_message = secure_symmetric_encrypt(message.encode(), session_cipher_key)
    return encrypted_message


def server_receive_message(encrypted_message, session_cipher_key):
    decrypted_message = secure_symmetric_decrypt(encrypted_message, session_cipher_key)
    return decrypted_message.decode()


def main():
    # Клієнт ініціює рукостискання
    client_random_data = client_hello()
    # Сервер генерує ключі та відповідає клієнту
    private_key, public_key = generate_key_pair()
    server_random_data, server_certificate = server_hello(public_key)

    # Обмін секретними рядками
    premaster_secret = b"secret_data"
    encrypted_premaster_secret = encrypt_premaster_secret(premaster_secret, public_key)
    decrypted_premaster_secret = decrypt_premaster_secret(encrypted_premaster_secret, private_key)

    # Генерація ключів сеансу
    cipher_key, auth_key = generate_session_keys(client_random_data, server_random_data, decrypted_premaster_secret)

    # Відправлення готовий повідомлення від клієнта
    client_ready_encrypted_message = client_ready_message(cipher_key)

    # Тут можна взаємодіяти з отриманими даними (наприклад, передавати їх через мережу)

    print("Client Random Data:", client_random_data)
    print("Server Random Data:", server_random_data)
    print("Server Certificate:", server_certificate.decode())
    print("Premaster Secret:", premaster_secret)
    print("Encrypted Premaster Secret:", encrypted_premaster_secret)
    print("Decrypted Premaster Secret:", decrypted_premaster_secret)
    print("Cipher Key:", cipher_key)
    print("Authentication Key:", auth_key)
    print("Client Ready Encrypted Message:", client_ready_encrypted_message)

    # Приклад передачі зашифрованого повідомлення
    client_message = "Hello from client!"
    encrypted_client_message = client_send_message(client_message, cipher_key)

    # Приклад отримання та розшифрування повідомлення на сервері
    server_received_message = server_receive_message(encrypted_client_message, cipher_key)
    print("Server Received Message:", server_received_message)


if __name__ == "__main__":
    main()
