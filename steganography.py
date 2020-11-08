

class Steganography:
    def __init__(self):
        self.image = None
        self.noBytes = None
        self.secretData = None
        
    def readImg(self, path):
        