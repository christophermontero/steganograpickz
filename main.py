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

dataAES = messageEncryptAES[0] + "." + messageEncryptAES[1] + "." + messageEncryptAES[2] # iv plus cipherText plus session Key

# Encrypt AES with RSA
rsa = alg.CipherRSA()
rsa.keyPair()
messageEncryptRSA = rsa.encrypted(dataAES)

# Decrypt with RSA
messageDecryptRSA = rsa.decrypted()

# Decrypt RSA with AES
messageDecryptAES = aesCBC.decrypted()
print(messageDecryptAES)
