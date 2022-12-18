from typing import List
import numpy as np
from PIL import Image, ImageFilter, ImageColor
import colorsys

IMAGE_FILE_NAME: str = 'test.png'


def Experiments():
    image = Image.open(IMAGE_FILE_NAME)
    # image.show()

    r, g, b = image.split()
    histogram = image.histogram()

    # print(r, g, b)
    # print(histogram)

    print(f'format = {image.format}')
    print(f'size = {image.size}')
    print(f'width = {image.width}')
    print(f'height = {image.height}')
    print(f'mode = {image.mode}')

    # rotated_img = image.rotate(80)
    # rotated_img.save('rotated_img.png')


def Detecting_Edges():
    image = Image.open(IMAGE_FILE_NAME)

    # Converting the image to grayscale, as edge detection
    # requires input image to be of mode = Grayscale (L)
    image = image.convert("L")

    # Detecting Edges on the Image using the argument ImageFilter.FIND_EDGES
    image = image.filter(ImageFilter.FIND_EDGES)

    # Saving the Image Under the name Edge_Sample.png
    image.save(r"Edge_Sample.png")


def ToNumpy():
    image = Image.open(IMAGE_FILE_NAME)
    img_arr = np.asarray(image.convert("L"))
    bg_color: int = img_arr[1][1]

    shape_lines: List[List[int]] = []
    for c in range(1, image.width - 1):
        line: List[int] = []
        for r in range(1, image.height - 1):
            # print(img_arr[r][c], "", end='')
            if img_arr[r][c] != bg_color:
                line.append(img_arr[r][c])
        if line:
            shape_lines.append(line)
        # print()

    for l in shape_lines:
        for i in l:
            print(i, "", end='')
        print()

    print(len(shape_lines))


def equals(list1: np.ndarray, list2: np.ndarray) -> bool:
    len1, len2 = len(list1), len(list2)
    if len1 != len2:
        return False
    for i in range(0, len1):
        if list1[i] != list2[i]:
            return False
    return True

def CheckCircleColor():
    import time
    start_time = time.time()

    image = Image.open(IMAGE_FILE_NAME)
    img_arr = np.asarray(image)
    forecolor = img_arr[1][1]

    print(type(forecolor), forecolor)

    shape: np.ndarray = []
    for c in range(1, image.width - 1):
        line: List[int] = []
        for r in range(1, image.height - 1):
            if not equals(img_arr[r][c], forecolor):
                line.append(img_arr[r][c])
        if line:
            shape.append(line)

    print(len(shape))
    print(shape[1][1])
    print(f"Time: {(time.time() - start_time)}")

    '''
    for l in shape:
        for i in l:
            print(i, "", end='')
        print()
    '''


def hue2rgb1(h):
    return tuple(round(i * 255) for i in colorsys.hsv_to_rgb(h / 360.0, 1, 1))


if __name__ == '__main__':
    # Experiments()
    # Detecting_Edges()
    ToNumpy()
    # CheckCircleColor()

    # r, g, b = colorsys.hsv_to_rgb(64 / 360.0, 1, 1)
    # print(r * 255, g * 255, b * 255)

    # print(hue2rgb1(64))
