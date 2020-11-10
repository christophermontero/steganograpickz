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

    def decrypted(self, message, privKey):
        recipientKey = RSA.import_key(privKey)
        cipherRSA = PKCS1_OAEP.new(recipientKey)
        self.decryptContent = cipherRSA.decrypt(message)

        return self.decryptContent


class CipherAES():
    def __init__(self):
        self.password = None
        self.plainText = None
        self.plainText2Bytes = None
        self.salt = None
        self.sessionKey = None
        self.cipherText = None
        self.iv = None
        self.plainTextDecrypt = None

    def expandSessionKey(self, password):
        self.salt = get_random_bytes(16)
        self.password = password
        expandKey = str.encode(self.password) + self.salt

        # Password is hashed
        h = MD5.new()
        h.update(expandKey)
        self.sessionKey = h.digest()

        return self.sessionKey

    def encrypted(self, text):
        self.plainText = text
        self.plainText2Bytes = str.encode(self.plainText)
        # Cipher AES is called
        cipherAES = AES.new(self.sessionKey, AES.MODE_CBC)
        self.cipherText = cipherAES.encrypt(pad(self.plainText2Bytes, AES.block_size))
        self.iv = cipherAES.iv

        return self.cipherText, self.iv, self.sessionKey

    def decrypted(self, cipherText, iv, sessionKey):
        cipherAES = AES.new(sessionKey, AES.MODE_CBC, iv)
        self.plainTextDecrypt = unpad(cipherAES.decrypt(cipherText), AES.block_size).decode('utf-8')

        return self.plainTextDecrypt
