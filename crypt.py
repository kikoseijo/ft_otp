from cryptography.fernet import Fernet

class Encryptor():

    def key_create(self):
        key = Fernet.generate_key()
        return key

    def key_write(self, key, key_name):
        with open(key_name, 'w') as key_file_name:
            key_file_name.write(key)

    def key_load(self, key_name):
        with open(key_name, 'rb') as key_file_name:
            key = key_file_name.read()
        return key

    def file_encrypt(self, key, original_file, encrypted_file):
        f = Fernet(key)
        with open(original_file, 'rb') as file:
            original = file.read()
        encrypted = f.encrypt(original)
        with open (encrypted_file, 'wb') as file:
            file.write(encrypted)

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        f = Fernet(key)
        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()
        decrypted = f.decrypt(encrypted)
        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)

    def get_decrypted_key(self, key, encrypted_file):
        f = Fernet(key)
        decrypted = f.decrypt(self.key_load(encrypted_file))
        return decrypted.decode("utf-8")
