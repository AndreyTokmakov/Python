from skimage import segmentation, io
from skimage.color import rgb2gray
import numpy as np
import matplotlib.pyplot as plt


IMAGE_FILE_NAME: str = 'test.png'



if __name__ == '__main__':
    image = io.imread(IMAGE_FILE_NAME)
    # gray_coffee = rgb2gray(image)

    plt.imshow(image);
    plt.show()