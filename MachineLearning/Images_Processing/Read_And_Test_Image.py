
import cv2
import numpy as np
from matplotlib import pyplot as pit


if __name__ == '__main__':
    # Создать дату
    image = cv2.imread("S:/Projects/TEST_DATA/Images/1359690.jpg", cv2.IMREAD_GRAYSCALE)

    '''
    pit.imshow(image, cmap="gray")
    pit.axis("off")
    pit.show()
    '''

    print(type(image))
    print(image)
    print(image.shape)