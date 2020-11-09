from base64 import b64encode

import algorithms as alg
import steganography as stegano


# The message is readed
fileUTF8 = open("message.txt","r")
message = fileUTF8.read()
fileUTF8.close()

# Encrypt message with AES
aesCBC = alg.CipherAES(message, "password")
aesCBC.expandSessionKey()
messageEncryptAES = aesCBC.encrypted()

dataAES = messageEncryptAES[0] + "." + messageEncryptAES[1] + "." + messageEncryptAES[2] # initial vector plus cipherText plus session Key

# Encrypt AES with RSA
rsa = alg.CipherRSA()
rsa.keyPair()
messageEncryptRSA = rsa.encrypted(dataAES)

# Decrypt with RSA
messageDecryptRSA = rsa.decrypted()

# Decrypt RSA with AES
messageDecryptAES = aesCBC.decrypted()
print(messageDecryptAES)


private = open("private.pem","r")
priv = private.read()
private.close()

public = open("private.pem","r")
pub = public.read()
public.close()

print(len(pub))
print(len(priv))

image = stegano.Steganography()
image.readImg("plain-text-password.jpg")
