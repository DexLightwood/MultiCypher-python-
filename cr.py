from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

def get_cipher(algo, key, iv):
    if algo == 'AES':
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif algo == 'DES':
        return Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    elif algo == '3DES':
        return Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    elif algo == 'RC2':
        return Cipher(algorithms.ARC2(key), modes.CBC(iv), backend=default_backend())
    elif algo == 'RC4':
        return Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    elif algo == 'IDEA':
        return Cipher(algorithms.IDEA(key), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError("Неподдерживаемый алгоритм")

def encrypt(data, algo, key, iv=None):
    cipher = get_cipher(algo, key, iv)
    encryptor = cipher.encryptor()
    if iv is not None:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()
    else:
        return encryptor.update(data) + encryptor.finalize()

def decrypt(encrypted_data, algo, key, iv=None):
    cipher = get_cipher(algo, key, iv)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    if iv is not None:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
    else:
        return decrypted_data

def main():
    algorithms = ['AES', 'DES', '3DES', 'RC2', 'RC4', 'IDEA']
    
    print("Доступные алгоритмы:")
    for i, algo in enumerate(algorithms, start=1):
        print(f"{i}. {algo}")

    algo_num = int(input("Выберите номер алгоритма: "))
    if algo_num < 1 or algo_num > len(algorithms):
        print("Неправильный номер алгоритма")
        return
    algo = algorithms[algo_num - 1]

    action = input("Вы хотите (1) зашифровать или (2) расшифровать? ")
    if action not in ['1', '2']:
        print("Неправильное действие")
        return

    text = input("Введите текст: ")
    data = text.encode('utf-8')

    key = input(f"Введите ключ (в шестнадцатеричном формате для {algo}): ")
    key = bytes.fromhex(key)
    
    iv = None
    if algo in ['AES', 'DES', '3DES', 'RC2', 'IDEA']:
        iv_input = input(f"Введите IV (в шестнадцатеричном формате для {algo}): ")
        iv = bytes.fromhex(iv_input)

    if action == '1':
        encrypted = encrypt(data, algo, key, iv)
        print("Зашифрованный текст:", base64.b64encode(encrypted).decode())
    elif action == '2':
        encrypted_data = base64.b64decode(data)
        decrypted = decrypt(encrypted_data, algo, key, iv)
        print("Расшифрованный текст:", decrypted.decode('utf-8'))

if __name__ == "__main__":
    main()
