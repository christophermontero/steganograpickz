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

# cipherText plus initial vector plus session key plus salt plus public key RSA plus fill
secretContent = messageEncryptAES[0] + messageEncryptAES[1] + sessionKeyEncryptRSA + aesCBC.salt + priv + image.filled(pub)

# Secret content is hidden into the image
imageEncrypted = image.encrypted(secretContent)

# The image tampered is saved
cv2.imwrite("image-tampered.png", imageEncrypted)

# The image is been decrypted
imageDecrypted = image.decrypted()

# Split content from image decrypted
cipherTextChunk = imageDecrypted[:len(messageEncryptAES[0])]
ivChunk = imageDecrypted[len(messageEncryptAES[0]) : len(messageEncryptAES[0]) + 16]
sessionKeyRSAChunk = imageDecrypted[len(messageEncryptAES[0]) + 16 : len(messageEncryptAES[0]) + 16 + 256]
saltChunk = imageDecrypted[len(messageEncryptAES[0]) + 16 + 256 : len(messageEncryptAES[0]) + 32 + 256]
privatekeyChunk = imageDecrypted[len(messageEncryptAES[0]) + 32 + 256 : len(messageEncryptAES[0]) + 32 + 256 + len(priv)]

# Decrypt session key with RSA
sessionKeyChunk = rsa.decrypted(sessionKeyRSAChunk, privatekeyChunk)
print(len(sessionKeyChunk))
print(sessionKeyChunk)

'''
# Decrypt RSA with AES
messageDecryptAES = aesCBC.decrypted(cipherTextChunk, ivChunk, sessionKeyChunk)

output = ("Cipher text: " + b64encode(cipherTextChunk).decode('utf-8') + "\n" +
          "Initial vector: " + b64encode(ivChunk).decode('utf-8') + "\n" +
          "Session key: " + b64encode(sessionKeyChunk).decode('utf-8') + "\n" +
          "Salt: " + b64encode(saltChunk).decode('utf-8') + "\n" +
          "Message: " + messageDecryptAES + "\n"
          )

outputDecrypted = open("output-decrypted.txt", "wb")
outputDecrypted.write(output)
outputDecrypted.close()
'''