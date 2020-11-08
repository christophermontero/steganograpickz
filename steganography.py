import cv2

class Steganography:
    def __init__(self):
        self.image = None
        self.noBytes = None
        self.secretData = None
        
    def readImg(self, path):
        self.image = cv2.imread(path)
        self.noBytes = self.image.shape[0] * self.image.shape[1] * 3 // 8
        