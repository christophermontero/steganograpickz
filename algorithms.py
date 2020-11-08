from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

class algRSA():
	self.publicKey = None
	self.privateKey = None

	def keyPair(self):
		key RSA.generate(2048)
		self.privateKey = key.export_key()
		self.publicKey = key.publicKey().export_key()

		return self.privateKey, self.publicKey