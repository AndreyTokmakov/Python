from skimage import segmentation, io
from skimage.color import rgb2gray
import numpy as np
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
from PIL import Image, ImageFilter


IMAGE_FILE_NAME: str = 'test.png'

if __name__ == '__main__':
    image = Image.open(IMAGE_FILE_NAME)
    X = np.asarray(image.convert("L"))
    # print(len(img_arr))

    kmeans = KMeans(n_clusters=1, random_state=0).fit(X)

    print(kmeans.cluster_centers_)
    print(X)