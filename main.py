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

        

    @classmethod
    def from_nbits(cls, nbits: int = 256):
        """Creates an AES encryption object with a new key with the given number of bits."""
        cls.key = get_random_bytes(32)
        
        cls.cipher = AES.new(cls.key,AES.MODE_CBC)

        return cls(cls.key)

    def encrypt(self, message: bytes) -> bytes:
        """Encrypts the given message using AES."""
        
        
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
        cls.key = RSA.generate(2048)

        return cls(cls.key)

    @classmethod
    def from_file(cls, filename: str, passphrase: str = None):
        """Creates an RSA encryption object with a key loaded from the given file."""
        f = open(filename,'rb')

        readKey = RSA.import_key(f.read(),passphrase=RSA_PASSPHRASE)

        cls.Cipher_RSA = PKCS1_OAEP.new(readKey.public_key())

        cls.key = readKey

        f.close()

        return cls(cls.key)

    def to_file(self, filename: str, passphrase: str = None):
        """Saves this RSA encryption object's key to the given file."""
        
        f = open(filename,'wb')

        f.write(self.key.export_key('PEM',passphrase=RSA_PASSPHRASE,pkcs=8,protection="scryptAndAES128-CBC"))

        f.close()

    def encrypt(self, message: bytes) -> bytes:
        """Encrypts the given message using RSA."""
        RSA_Encrypted = self.Cipher_RSA.encrypt(message)

        return RSA_Encrypted

    def decrypt(self, message: bytes) -> bytes:
        """Decrypts the given message using RSA."""
        
        decryptor = PKCS1_OAEP.new(self.key)
        
        plaintext = decryptor.decrypt(message)

        return plaintext




class HybridEncryption:
    """Uses RSA and AES encryption (hybrid cryptosystem) to encrypt (large) messages."""

    def __init__(self, rsa: RSAEncryption) -> None:
        self.rsa = rsa
        self.iv = None

    def encrypt(self, message: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts the given message using a hybrid cryptosystem (AES and RSA).
        Returns the encrypted message and the encrypted symmetric key.
        """
        AES_key = get_random_bytes(32)

        AES_cipher = AES.new(AES_key,AES.MODE_CBC)

        self.iv = AES_cipher.iv

        EncryptedMessage = AES_cipher.encrypt(pad(message,AES.block_size))

        Encrypted_Symmetric_Key = self.rsa.Cipher_RSA.encrypt(AES_key)

        return (EncryptedMessage,Encrypted_Symmetric_Key)


        

    def decrypt(self, message: bytes, message_key: bytes) -> bytes:
        """
        Encrypts the given message using a hybrid cryptosystem (AES and RSA).
        Requires the encrypted symmetric key that the message was encrypted with.
        """
        
        decryptor = PKCS1_OAEP.new(self.rsa.key)

        decryptedSymmetricKey = decryptor.decrypt(message_key)

        SymmetricDecryptCipher = AES.new(decryptedSymmetricKey, AES.MODE_CBC,self.iv)

        plaintext = unpad (SymmetricDecryptCipher.decrypt(message),AES.block_size)

        return plaintext


class DigitalSignature:
    """Uses RSA encryption and SHA-256 hashing to create/verify digital signatures."""

    def __init__(self, rsa: RSAEncryption) -> None:
        self.rsa = rsa

    def sign(self, message: bytes) -> bytes:
        """Signs the given message using RSA and SHA-256 and returns the digital signature."""
        
        m = SHA256.new()

        m.update(message)
        
        HashedMessaage = self.rsa.Cipher_RSA.encrypt(m.digest())

        return HashedMessaage

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verifies the digital signature of the given message using RSA and SHA-256."""
        

        decryptor = PKCS1_OAEP.new(self.rsa.key)
        
        decryptedHashMessage = decryptor.decrypt(signature)

        m = SHA256.new()

        m.update(message)

        return (m.digest() == decryptedHashMessage )



if __name__ == "__main__":
    # Messages and Keys
    MESSAGE = b"This is a test message."

    # b"This is a test message."
    MESSAGE_LONG = get_random_bytes(100_000)
    LOREM = "lorem.txt"

    RSA_KEY = "rsa_key.pem"
    RSA_KEY_TEST = "rsa_key_test.pem"
    RSA_SIG = "rsa_sig.pem"
    RSA_PASSPHRASE = "123456"

    # AES
    aes = AESEncryption.from_nbits(256)
  
    encrypted_msg = aes.encrypt(MESSAGE)
    decrypted_msg = aes.decrypt(encrypted_msg)
    print("[AES] Successfully Decrypted:", MESSAGE == decrypted_msg)

    # RSA
    rsa = RSAEncryption.from_file(RSA_KEY, RSA_PASSPHRASE)
    encrypted_msg = rsa.encrypt(MESSAGE)
    decrypted_msg = rsa.decrypt(encrypted_msg)
    print("[RSA] Successfully Decrypted:", MESSAGE == decrypted_msg)

    rsa.to_file(RSA_KEY_TEST, RSA_PASSPHRASE)
    rsa_test = RSAEncryption.from_file(RSA_KEY_TEST, RSA_PASSPHRASE)
    print("[RSA] Successfully Imported/Exported:", rsa.key == rsa_test.key)
    os.remove(RSA_KEY_TEST)

    # Hybrid
    with open(LOREM, "rb") as f:
        lorem = f.read()

    hybrid = HybridEncryption(rsa)
    encrypted_msg, encrypted_msg_key = hybrid.encrypt(lorem)
    
    decrypted_msg = hybrid.decrypt(encrypted_msg, encrypted_msg_key)
    print("[HYBRID] Successfully Decrypted:", decrypted_msg == lorem)

    # Digital Signature
    signer = DigitalSignature(RSAEncryption.from_file(RSA_KEY, RSA_PASSPHRASE))
    encrypted_msg, encrypted_msg_key = hybrid.encrypt(MESSAGE_LONG)
    msg_signature = signer.sign(encrypted_msg)

    modified_msg = bytearray(encrypted_msg)
    modified_msg[1000] ^= 0xFF  # invert bits of byte
    modified_msg = bytes(modified_msg)

    print("[SIG] Original Valid:", signer.verify(encrypted_msg, msg_signature))
    print("[SIG] Modified NOT Valid:", not signer.verify(modified_msg, msg_signature))

    decrypted_msg = hybrid.decrypt(encrypted_msg, encrypted_msg_key)
    print("[SIG] Original Successfully Decrypted:", MESSAGE_LONG == decrypted_msg)

    decrypted_msg = hybrid.decrypt(modified_msg, encrypted_msg_key)
    print("[SIG] Modified Fails Decryption:", MESSAGE_LONG != decrypted_msg)
