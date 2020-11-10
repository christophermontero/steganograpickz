from base64 import b64encode
import cv2
import algorithms as alg
import steganography as stegano

# The message is readed
fileUTF8 = open("message.txt", "r")
message = fileUTF8.read()
fileUTF8.close()

# Encrypt message with AES
print("The message is been encrypted with AES...")
aesCBC = alg.CipherAES(message, "password")
aesCBC.expandSessionKey()
messageEncryptAES = aesCBC.encrypted()
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
public = open("public.pem", "r")
pub = public.read()
public.close()

# Secret content to be hidden into a image
image = stegano.Steganography()
image.readImg("plain-text-password.jpg")

# cipherText plus initial vector plus session key plus salt plus private key RSA plus fill
secretContent = messageEncryptAES[0] + "separator" + messageEncryptAES[1] + "separator" + sessionKeyEncryptRSA + "separator" + aesCBC.salt + "separator" + priv + "separator" + image.filled(messageEncryptAES[0], priv)

# Secret content is hidden into the image
print("The secret content is been hidden into a image...")
imageEncrypted = image.encrypted(secretContent)
print("Secret content hidden")

# The image tampered is saved
cv2.imwrite("image-tampered.png", imageEncrypted)

# The image is been decrypted
print("The image is been decrypted...")
imageDecrypted = image.decrypted()

# The secret content is separated
splitSecretContent = imageDecrypted.split('separator')

# Decrypt session key with RSA
print("The session key is been decrypted with RSA...")
sessionKeyDecryptRSA = rsa.decrypted(splitSecretContent[2], splitSecretContent[4])
print("Session key decrypted with RSA")

# Decrypt RSA with AES
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
