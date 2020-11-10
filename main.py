import argparse
from base64 import b64encode
import cv2
import algorithms as alg
import steganography as stegano


def hiddenMesg(pick, password):
	# The message is readed
	fileUTF8 = open("message.txt", "r")
	message = fileUTF8.read()
	fileUTF8.close()

	# Encrypt message with AES
	print("The message is been encrypted with AES...")
	aesCBC = alg.CipherAES()
	aesCBC.expandSessionKey(password)
	messageEncryptAES = aesCBC.encrypted(message)
	print("Message encrypted with AES")

	# Encrypt AES session key with RSA
	print("The session key is been encrypted with RSA...")
	rsa = alg.CipherRSA()
	rsa.keyPair()
	sessionKeyEncryptRSA = rsa.encrypted(messageEncryptAES[2])
	print("Session key encrypted with RSA")

	# Key pairs are readed
	private = open("private.pem", "r")
	priv = private.read()
	private.close()

	# Secret content to be hidden into a image
	image = stegano.Steganography()
	image.readImg(pick)

	# cipherText plus initial vector plus session key plus salt plus private key RSA plus fill
	secretContent = messageEncryptAES[0] + "separator" + messageEncryptAES[1] + "separator" + sessionKeyEncryptRSA + "separator" + aesCBC.salt + "separator" + priv + "separator" + image.filled(messageEncryptAES[0], priv)

	# Secret content is hidden into the image
	print("The secret content is been hidden into a image...")
	imageEncrypted = image.encrypted(secretContent)
	print("Secret content hidden")

	# The image tampered is saved
	cv2.imwrite("image-tampered.png", imageEncrypted)

def extracMsg(pick, password):
	# The image is been decrypted
	print("The image is been decrypted...")
	image = stegano.Steganography()
	imgTampered = cv2.imread(pick)
	imageDecrypted = image.decrypted(imgTampered)

	# The secret content is separated
	splitSecretContent = imageDecrypted.split('separator')

	# Decrypt session key with RSA
	print("The session key is been decrypted with RSA...")
	rsa = alg.CipherRSA()
	sessionKeyDecryptRSA = rsa.decrypted(splitSecretContent[2], splitSecretContent[4])
	print("Session key decrypted with RSA")

	# Decrypt RSA with AES
	aesCBC = alg.CipherAES()
	messageDecryptAES = aesCBC.decrypted(splitSecretContent[0], splitSecretContent[1], sessionKeyDecryptRSA)

	output = ("Cipher text: " + b64encode(splitSecretContent[0]).decode('utf-8') + "\n" +
	          "Initial vector: " + b64encode(splitSecretContent[1]).decode('utf-8') + "\n" +
	          "Session key: " + b64encode(sessionKeyDecryptRSA).decode('utf-8') + "\n" +
	          "Salt: " + b64encode(splitSecretContent[3]).decode('utf-8') + "\n" +
	          "Private key: " + splitSecretContent[4] + "\n"
	          "Message: " + messageDecryptAES
	          )

	outputDecrypted = open("output-decrypted.txt", "wb")
	outputDecrypted.write(output)
	outputDecrypted.close()
	print("Image decrypted")

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Steganography schema, which use AES-CBC and RSA')

	# Declare arguments to pass from console
	parser.add_argument('pick', help='Insert the name of image as input')
	parser.add_argument('password', help='Enter your password for AES-CBC')
	parser.add_argument("--hidden", action="store_true", help='Use to hide a message into a image')
	parser.add_argument("--extrac", action="store_true", help='If you want extract a message from image use this')

	args = parser.parse_args()

	if args.hidden:
		hiddenMesg(args.pick, args.password)
	else args.extrac:
		extracMsg(args.pick, args.password)
