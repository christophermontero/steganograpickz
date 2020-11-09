from base64 import b64encode
import cv2

import algorithms as alg
import steganography as stegano


# The message is readed
fileUTF8 = open("message.txt", "r")
message = fileUTF8.read()
fileUTF8.close()

# Encrypt message with AES
aesCBC = alg.CipherAES(message, "password")
aesCBC.expandSessionKey()
messageEncryptAES = aesCBC.encrypted()

# cipherText plus initial vector
dataAES = messageEncryptAES[0] + "." + messageEncryptAES[1]

# Encrypt AES session key with RSA
rsa = alg.CipherRSA()
rsa.keyPair()
sessionKeyEncryptRSA = rsa.encrypted(messageEncryptAES[2])

# Key pairs are readed
private = open("private.pem", "r")
priv = private.read()
private.close()
public = open("public.pem", "r")
pub = public.read()
public.close()

# Secret content to be hidden into a image
image = stegano.Steganography()
image.readImg("plain-text-password.jpg")
secretContent = sessionKeyEncryptRSA + pub + image.filled(pub)
imageEncrypted = image.encrypted(secretContent)

# The image is been decrypted
imageDecrypted = image.decrypted()
dataAESEncrypt = secretContent[:256]
cv2.imwrite("image-tampered.png", imageEncrypted)

# Decrypt with RSA
messageDecryptRSA = rsa.decrypted(dataAESEncrypt)
splitMessage = messageDecryptRSA.split('.')

print(len(aesCBC.cipherText))
print(len(aesCBC.iv))
print(len(aesCBC.sessionKey))

# Decrypt RSA with AES
messageDecryptAES = aesCBC.decrypted(splitMessage[0], splitMessage[1], splitMessage[2])

output = ("Cipher text: " + b64encode(splitMessage[0]).decode('utf-8') + "\n" +
          "Initial vector: " + b64encode(splitMessage[1]).decode('utf-8') + "\n" +
          "Session key: " + b64encode(splitMessage[2]).decode('utf-8') + "\n" +
          "Salt: " + b64encode(aesCBC.salt).decode('utf-8') + "\n" +
          "Message: " + messageDecryptAES + "\n"
          )

outputDecrypted = open("output-decrypted.txt", "wb")
outputDecrypted.write(output)
outputDecrypted.close()
