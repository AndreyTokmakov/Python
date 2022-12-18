import os

import cv2
import cv2 as cv
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

TEST_DIR_PATH: Path = Path("/home/andtokm/DiskS/ProjectsUbuntu/TEST_DATA/")
FACES_DIR: Path = Path(os.path.join(TEST_DIR_PATH, "faces"))


def cv_show_image(image: np.ndarray, wnd_text: str = "OpenCV Window") -> None:
    cv.imshow(wnd_text, image)

    # Using cv2.imshow() method  Displaying the image
    cv.waitKey(0)

    # closing all open windows
    cv.destroyAllWindows()


def read_and_show_image():
    file_path: str = os.path.join(TEST_DIR_PATH, "arches-national-park-1846759_960_720.jpg")

    img = cv.imread(file_path)

    cv_show_image(img)

    # cv.imwrite(file_path + "___", img)


def displaying_images_with_matplotlib():
    file_path: str = os.path.join(TEST_DIR_PATH, "arches-national-park-1846759_960_720.jpg")
    img = cv.imread(file_path)
    plt.imshow(img, cmap='gray', interpolation='bicubic')
    plt.show()


def detect_face_simple_test():
    file_path: str = os.path.join(FACES_DIR, 'face_1.jpg')
    file_path_dest: str = os.path.join(FACES_DIR, 'face_1_edges.jpg')

    img: np.ndarray = cv.imread(file_path)
    cv.imwrite(file_path_dest, cv.Canny(img, 602, 315))

    cv_show_image(cv.imread(file_path_dest))


if __name__ == '__main__':
    # print(f"OpenCV experiments. Version {cv.__version__}")

    # read_and_show_image()
    # displaying_images_with_matplotlib()
    detect_face_simple_test()
