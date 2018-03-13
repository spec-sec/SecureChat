"""
Diffie-Hellman Key Exchange class for establishing a shared key.
"""

from Crypto import Random
import binascii
from hashlib import sha256

__author__ = "spec"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "Development"

# Size of prime number in bits (recommended minimum: 2048)
DH_SIZE = 2048

# Length (in bytes) of each variable for public transport
LEN_PRIME = 1024
LEN_GEN = 16
LEN_PK = 1024

# Total public transport message size (in bytes)
DH_MSG_SIZE = LEN_PRIME + LEN_GEN + LEN_PK


class DH:

    def __init__(self, p, g, pk):
        """
        Initialize a new DH object for key exchange between client and server.
        :param p: a prime number from the multiplicative group of integers modulo n
        :param g: primitive root modulo
        :param pk: public key generated from p, g, and a private key
        """
        self.p = p
        self.g = g
        self.pk = pk

    @staticmethod
    def gen_private_key():
        """
        Generate a random private key.
        :return: a random integer of length DH_SIZE
        """
        return DH.b2i(Random.new().read(DH_SIZE))

    @staticmethod
    def gen_public_key(g, private, p):
        """
        Generate a public key from g, p, and a private key.
        :param g: primitive root modulo
        :param private: private key
        :param p: prime number
        :return: public key as an integer
        """
        return pow(g, private, p)

    @staticmethod
    def get_shared_key(public, private, p):
        """
        Calculate a shared key from a foreign public key, a local private
        key, and a shared prime.
        :param public: public key as an integer
        :param private: private key as an integer
        :param p: prime number
        :return: shared key as a 256-bit bytes object
        """
        s = pow(public, private, p)
        s_hex = hex(s)[2:]
        # Make the length of s_hex a multiple of 2
        if len(s_hex) % 2 != 0:
            s_hex = '0' + s_hex
        # Convert hex to bytes
        s_bytes = binascii.unhexlify(s_hex)
        # Hash and return the hex result
        return sha256(s_bytes).digest()

    @staticmethod
    def b2i(bts):
        """
        Convert a bytes object to an integer.
        :param bts: bytes to convert
        :return: integer
        """
        return int(binascii.hexlify(bts), 16)

    @staticmethod
    def package(i, length):
        """
        Package an integer as a bytes object of length "length".
        :param i: integer to be package
        :param length: desired length of the bytes object
        :return: bytes representation of the integer
        """
        # Convert i to hex and remove '0x' from the left
        i_hex = hex(i)[2:]
        # Make the length of i_hex a multiple of 2
        if len(i_hex) % 2 != 0:
            i_hex = '0' + i_hex
        # Convert hex string into bytes
        i_bytes = binascii.unhexlify(i_hex)
        # Check to make sure bytes to not exceed the max length
        len_i = len(i_bytes)
        if len_i > length:
            raise InvalidDH("Length Exceeds Maximum of {}".format(length))
        # Generate padding for the remaining space on the left
        i_padding = bytes(length - len_i)
        return i_padding + i_bytes

    @staticmethod
    def unpack(dh_message):
        """
        Unpack a bytes object into its component p, g, and pk values.
        :param dh_message: received bytes object
        :return: p: shared prime, g: primitive root modulo, pk: public key
        """
        # Separate message into components
        p_bytes = dh_message[:LEN_PRIME]
        g_bytes = dh_message[LEN_PRIME:LEN_PRIME+LEN_GEN]
        pk_bytes = dh_message[-1 * LEN_PK:]
        # Convert bytes to integers
        p = DH.b2i(p_bytes)
        g = DH.b2i(g_bytes)
        pk = DH.b2i(pk_bytes)
        return p, g, pk

    def __bytes__(self):
        """
        Convert DH message to bytes.
        :return: packaged DH message as bytes
        +-------+-----------+------------+
        | Prime | Generator | Public Key |
        |  1024 |    16     |    1024    |
        +-------+-----------+------------+
        """
        prm = self.package(self.p, LEN_PRIME)
        gen = self.package(self.g, LEN_GEN)
        pbk = self.package(self.pk, LEN_PK)
        return prm + gen + pbk


class InvalidDH(Exception):

    def __init__(self, message):
        self.message = message
