import cv2
import numpy as np
from Crypto.Random import get_random_bytes

class Steganography:
    def __init__(self):
        self.image = None
        self.noBytes = None
        self.secretData = None
        self.padding = None
        
    def readImg(self, path):
        self.image = cv2.imread(path)
        self.noBytes = self.image.shape[0] * self.image.shape[1] * 3 // 8

    def filled(self, publicKey):
    	randomFill = self.noBytes - (256 + len(publicKey))
    	self.padding = get_random_bytes(randomFill)

    	return self.padding

    def binary(self, data):
		if isinstance(data, str):
			return ''.join([ format(ord(i), "08b") for i in data ])
		elif isinstance(data, bytes):
			return ''.join([ format(i, "08b") for i in data ])
		elif isinstance(data, np.ndarray):
			return [ format(i, "08b") for i in data ]
		elif isinstance(data, int) or isinstance(data, np.uint8):
			return format(data, "08b")
		else:
			raise TypeError("Type not supported.")

    def encrypted(self, content):
    	self.secretData = content
        dataIndex = 0
        secretDataBinary = self.binary(self.secretData)

        # s
        for row in self.image:
            for pixel in row:
                for channel in range(len(pixel)): # channel representa el canal, (R,G,B)
                    if dataIndex < len(secretDataBinary):
                        pixel[channel] = int(self.binary(pixel[channel])[:-1] + secretDataBinary[dataIndex],2)
                        dataIndex += 1
                    else:
                        break
        return self.image

    def decrypted(self):
        binaryData = ""
        for row in self.image:
            for pixel in row:
                r, g, b = self.binary(pixel)
                binaryData += r[-1]
                binaryData += g[-1]
                binaryData += b[-1]

        # Bytes list
        allBytes = [binaryData[ i: i+8] for i in range(0, len(binaryData), 8)]

        # Clean last byte
        if len(allBytes[-1]) != 8:
            allBytes = allBytes[:-1]

        # Convert bytes to string
        decryptData = ""
        for byte in allBytes:
            decryptData += chr(int(byte, 2))

        return decryptData
