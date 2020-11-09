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

# initial vector plus cipherText plus session Key
dataAES = messageEncryptAES[0] + "." + \
    messageEncryptAES[1] + "." + messageEncryptAES[2]

# Encrypt AES with RSA
rsa = alg.CipherRSA()
rsa.keyPair()
messageEncryptRSA = rsa.encrypted(dataAES)

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
secretContent = messageEncryptRSA + pub + image.filled(pub)
imageEncrypted = image.encrypted(secretContent)

# The image is been decrypted
imageDecrypted = image.decrypted()
dataAESEncrypt = secretContent[:256]
cv2.imwrite("image-tampered.PNG", imageEncrypted)

# Decrypt with RSA
messageDecryptRSA = rsa.decrypted(dataAESEncrypt)
splitMessage = messageDecryptRSA.split('.')

# Decrypt RSA with AES
messageDecryptAES = aesCBC.decrypted(splitMessage[0], splitMessage[1], splitMessage[2])

output = ("Cipher text: " + b64encode(splitMessage[0]).decode('utf-8') + "\n" +
          "Initial vector: " + b64encode(splitMessage[1]).decode('utf-8') + "\n" +
          "Session key: " + b64encode(splitMessage[2]).decode('utf-8') + "\n" +
          "Message: " + messageDecryptAES + "\n"
          )

print(output)
