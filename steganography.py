import cv2
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

    def filled(self):
    	randomFill = self.noBytes - (256 + 1674)
    	self.padding = get_random_bytes(randomFill)

    	return self.padding
        