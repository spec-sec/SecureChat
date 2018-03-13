"""
Handles the encryption and decryption of messages using AES.
"""

from Crypto.Cipher import AES
from Crypto import Random

__author__ = "spec"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "Development"


class Message:

    def __init__(self, key, plaintext=None, ciphertext=None):
        """
        Initialize a new message object from a key and either plaintext
        or cipher-text.
        :param key: shared key to use for encryption/decryption
        :param plaintext: plaintext message
        :param ciphertext: encrypted message
        """
        self.key = key
        # If plaintext is specified, generate its encrypted counterpart
        if plaintext:
            self.plaintext = plaintext
            self.ciphertext, self.iv = self.encrypt()
        # If instead cipher-text is specified, decrypt it
        elif ciphertext:
            self.ciphertext = ciphertext
            self.plaintext, self.iv = self.decrypt()
        # Otherwise declaration is invalid
        else:
            raise InvalidMessage("Either plaintext or cipher-text must be declared")

    def encrypt(self):
        """
        Encrypt a plaintext message.
        :return: the encrypted message and its corresponding initialization vector
        """
        # Generate a randomized initialization vector
        iv = Random.new().read(AES.block_size)
        # Create a new AES object in Cipher Block Chaining mode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Add a buffer so that the plaintext is a multiple of 16 characters in length
        pt_len = len(self.plaintext)
        buffer_size = AES.block_size - pt_len % AES.block_size
        return cipher.encrypt(self.plaintext + " " * buffer_size), iv

    def decrypt(self):
        """
        Decrypt a cipher-text message.
        :return: the decrypted message and its corresponding initialization vector
        """
        # Grab the initialization vector from the front of the cipher-text
        iv = self.ciphertext[:AES.block_size]
        # Create a new AES object in Cipher Block Chaining mode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(self.ciphertext)[AES.block_size:].rstrip().decode("utf-8"), iv

    def pack(self):
        """
        Package the message as an encrypted bytes object.
        :return: encrypted bytes
        """
        return self.iv + self.ciphertext


class InvalidMessage(Exception):

    def __init__(self, msg):
        self.msg = msg
