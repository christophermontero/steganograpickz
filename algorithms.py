from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


class AlgRSA():
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

    def encrypt(self, content):
        recipientKey = RSA.import_key(open("public.pem").read())
        cipherRSA = PKCS1_OAEP.new(recipientKey)
        self.encryptContent = cipherRSA.encrypt(content)

        return self.encryptContent

    def decrypt(self):
        recipientKey = RSA.import_key(open("private.pem").read())
        cipherRSA = PKCS1_OAEP.new(recipientKey)
        self.decryptContent = cipherRSA.decrypt(self.encryptContent)

        return self.decryptContent
