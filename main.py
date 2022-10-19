import os
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad




class AESEncryption:
    """Encrypts/decrypts messages using AES encryption with the given key."""
    
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.cipher = ""

    @classmethod
    def from_nbits(cls, nbits: int = 256):
        """Creates an AES encryption object with a new key with the given number of bits."""
        cls.key = get_random_bytes(32)
        
        cls.cipher = AES.new(cls.key,AES.MODE_CBC) 

  
        return cls.cipher

    def encrypt(self, message: bytes) -> bytes:
        """Encrypts the given message using AES."""
        
        print(AES.block_size)
        ciphertext = self.cipher.encrypt(pad(message,AES.block_size))

     
        return ciphertext
        
        
        
    def decrypt(self, message: bytes) -> bytes:
        """Decrypts the given message using AES."""

        decryptIV = self.cipher.iv

        deCryptCipher = AES.new(self.key, AES.MODE_CBC,decryptIV)

        plaintext = unpad (deCryptCipher.decrypt(message),AES.block_size)

        return plaintext
        


class RSAEncryption:
    """Encrypts/decrypts messages using RSA encryption with the given key."""

    def __init__(self, key: RSA.RsaKey) -> None:
        self.key = key

    @classmethod
    def from_nbits(cls, nbits: int = 2048):
        """Creates an RSA encryption object with a new key with the given number of bits."""
        cls.key = RSA.newKeys(2048)

    @classmethod
    def from_file(cls, filename: str, passphrase: str = None):
        """Creates an RSA encryption object with a key loaded from the given file."""
        

    def to_file(self, filename: str, passphrase: str = None):
        """Saves this RSA encryption object's key to the given file."""
        pass

    def encrypt(self, message: bytes) -> bytes:
        """Encrypts the given message using RSA."""
        pass

    def decrypt(self, message: bytes) -> bytes:
        """Decrypts the given message using RSA."""
        pass


class HybridEncryption:
    """Uses RSA and AES encryption (hybrid cryptosystem) to encrypt (large) messages."""

    def __init__(self, rsa: RSAEncryption) -> None:
        self.rsa = rsa

    def encrypt(self, message: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts the given message using a hybrid cryptosystem (AES and RSA).
        Returns the encrypted message and the encrypted symmetric key.
        """
        

    def decrypt(self, message: bytes, message_key: bytes) -> bytes:
        """
        Encrypts the given message using a hybrid cryptosystem (AES and RSA).
        Requires the encrypted symmetric key that the message was encrypted with.
        """
        pass


class DigitalSignature:
    """Uses RSA encryption and SHA-256 hashing to create/verify digital signatures."""

    def __init__(self, rsa: RSAEncryption) -> None:
        self.rsa = rsa

    def sign(self, message: bytes) -> bytes:
        """Signs the given message using RSA and SHA-256 and returns the digital signature."""
        pass

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verifies the digital signature of the given message using RSA and SHA-256."""
        pass


if __name__ == "__main__":
    # Messages and Keys
    MESSAGE = b"This is a test message."
    MESSAGE_LONG = get_random_bytes(100_000)
    LOREM = "lorem.txt"

    RSA_KEY = "rsa_key.pem"
    RSA_KEY_TEST = "rsa_key_test.pem"
    RSA_SIG = "rsa_sig.pem"
    RSA_PASSPHRASE = "123456"

    # AES
    aes = AESEncryption.from_nbits(256)
    # No error when added pad(MESSAGE,AES.block_size)
    encrypted_msg = aes.encrypt(pad(MESSAGE,AES.block_size))
    
    # Error
    encrypted_msg = aes.encrypt(MESSAGE)
    
    # decrypted_msg = aes.decrypt(encrypted_msg)
    # print("[AES] Successfully Decrypted:", MESSAGE == decrypted_msg)

    # RSA
    # rsa = RSAEncryption.from_file(RSA_KEY, RSA_PASSPHRASE)
    # encrypted_msg = rsa.encrypt(MESSAGE)
    # decrypted_msg = rsa.decrypt(encrypted_msg)
    # print("[RSA] Successfully Decrypted:", MESSAGE == decrypted_msg)

    # rsa.to_file(RSA_KEY_TEST, RSA_PASSPHRASE)
    # rsa_test = RSAEncryption.from_file(RSA_KEY_TEST, RSA_PASSPHRASE)
    # print("[RSA] Successfully Imported/Exported:", rsa.key == rsa_test.key)
    # os.remove(RSA_KEY_TEST)

    # # Hybrid
    # with open(LOREM, "rb") as f:
    #     lorem = f.read()

    # hybrid = HybridEncryption(rsa)
    # encrypted_msg, encrypted_msg_key = hybrid.encrypt(lorem)
    # decrypted_msg = hybrid.decrypt(encrypted_msg, encrypted_msg_key)
    # print("[HYBRID] Successfully Decrypted:", decrypted_msg == lorem)

    # # Digital Signature
    # signer = DigitalSignature(RSAEncryption.from_file(RSA_SIG, RSA_PASSPHRASE))
    # encrypted_msg, encrypted_msg_key = hybrid.encrypt(MESSAGE_LONG)
    # msg_signature = signer.sign(encrypted_msg)

    # modified_msg = bytearray(encrypted_msg)
    # modified_msg[1000] ^= 0xFF  # invert bits of byte
    # modified_msg = bytes(modified_msg)

    # print("[SIG] Original Valid:", signer.verify(encrypted_msg, msg_signature))
    # print("[SIG] Modified NOT Valid:", not signer.verify(modified_msg, msg_signature))

    # decrypted_msg = hybrid.decrypt(encrypted_msg, encrypted_msg_key)
    # print("[SIG] Original Successfully Decrypted:", MESSAGE_LONG == decrypted_msg)

    # decrypted_msg = hybrid.decrypt(modified_msg, encrypted_msg_key)
    # print("[SIG] Modified Fails Decryption:", MESSAGE_LONG != decrypted_msg)
