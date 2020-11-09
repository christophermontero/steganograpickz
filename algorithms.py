from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CipherRSA():
    def __init__(self):
        self.publicKeyRSA = None
        self.privateKeyRSA = None
        self.encryptContent = None
        self.decryptContent = None

    def keyPair(self):
        key = RSA.generate(2048)
        # Private key is being generated
        self.privateKeyRSA = open("private.pem", "wb")
        self.privateKeyRSA.write(key.export_key())
        self.privateKeyRSA.close()

        # Public key is being generated
        self.publicKeyRSA = open("public.pem", "wb")
        self.publicKeyRSA.write(key.publickey().export_key())
        self.publicKeyRSA.close()

    def encrypted(self, content):
        recipientKey = RSA.import_key(open("public.pem").read())
        cipherRSA = PKCS1_OAEP.new(recipientKey)
        self.encryptContent = cipherRSA.encrypt(content)

        return self.encryptContent

    def decrypted(self, message):
        recipientKey = RSA.import_key(open("private.pem").read())
        cipherRSA = PKCS1_OAEP.new(recipientKey)
        self.decryptContent = cipherRSA.decrypt(message)

        return self.decryptContent


class CipherAES():
    def __init__(self, text, password):
        self.password = password
        self.plainText = text
        self.plainText2Bytes = str.encode(self.plainText)
        self.salt = None
        self.sessionKey = None
        self.cipherText = None
        self.iv = None
        self.plainTextDecrypt = None

    def expandSessionKey(self):
        self.salt = get_random_bytes(16)
        expandKey = str.encode(self.password) + self.salt

        # Password is hashed
        h = MD5.new()
        h.update(expandKey)
        self.sessionKey = h.digest()

        return self.sessionKey

    def encrypted(self):
        # Cipher AES is called
        cipherAES = AES.new(self.sessionKey, AES.MODE_CBC)
        self.cipherText = cipherAES.encrypt(pad(self.plainText2Bytes, AES.block_size))
        self.iv = cipherAES.iv

        return self.cipherText, self.iv, self.sessionKey

    def decrypted(self):
        cipherAES = AES.new(self.sessionKey, AES.MODE_CBC, self.iv)
        self.plainTextDecrypt = unpad(cipherAES.decrypt(self.cipherText), AES.block_size).decode('utf-8')

        return self.plainTextDecrypt
