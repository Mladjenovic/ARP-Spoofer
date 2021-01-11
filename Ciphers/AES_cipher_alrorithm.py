import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size # 128 by default (AES def)
        self.key = hashlib.sha256(key.encode()).digest() # unique key for crypting

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size # number of bytes (in integer format)
        ascii_string = chr(number_of_bytes_to_pad) # exact number (represented as char) of chars that need to be padded
        padding_str = number_of_bytes_to_pad * ascii_string # string = char * num_of_chars
        padded_plain_text = plain_text + padding_str # string that is a multiple of 128bit 
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character) # ord --> reverse of char
        return plain_text[:-bytes_to_remove]

    
    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode('utf-8')

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)



if __name__ == "__main__":

    AESCipher_object = AESCipher('kljuc')
    message = 'husa_123'
    cipher_key = AESCipher_object.key
    encrypted = AESCipher_object.encrypt(message)
    decrypted = AESCipher_object.decrypt(encrypted)
    print("message is: ", message)
    print("Encrypted: ", encrypted)
    print("Decrypted: ", decrypted)
    print("AES done using key: ", cipher_key)
