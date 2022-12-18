import numpy as np
from typing import List, Tuple
from PIL import Image

class ShapeWrapper(object):
    BORDER_SIZE: int = 1

    def __init__(self, image_path: str) -> None:
        self.image = Image.open(image_path)
        self.width: int = 0
        self.height: int = 0
        self.__initialize(self.image)

    # Assuming that image has 1-pixel border
    # Assuming that all circle pixel has same color
    def __initialize(self, image: Image) -> None:
        pixels: np.ndarray = np.asarray(image)
        forecolor = pixels[1][1]

        # self.shape - to use/analyze circle data later (it required)
        self.shape: np.ndarray = []
        for c in range(1, image.width - self.BORDER_SIZE):
            line: List[int] = []
            for r in range(1, image.height - self.BORDER_SIZE):
                if not ShapeWrapper.equal_color(pixels[r][c], forecolor):
                    line.append(pixels[r][c])
            if line:
                self.shape.append(line)
                self.width = max(self.width, len(line))

        self.height = len(self.shape)

    def getDiameter(self) -> int:
        if self.width == self.height:
            return self.height
        else:
            raise Exception("Ouch!It looks like it's not a circle")

    def getCircleColor(self) -> Tuple[int, int, int]:
        return tuple(self.shape[0][0]) if len(self.shape) > 0 else (255, 0, 0)

    @staticmethod
    def equal_color(list1: np.ndarray,
                    list2: np.ndarray) -> bool:
        len1, len2 = len(list1), len(list2)
        if len1 != len2:
            return False
        for i in range(0, len1):
            if list1[i] != list2[i]:
                return False
        return True

    @staticmethod
    def hue2rgb(h):
        import colorsys
        return tuple(round(i * 255) for i in colorsys.hsv_to_rgb(h / 360.0, 1, 1))

    def Test(self):
        print(f'height: {self.height}, width: {self.width}')
        for l in self.shape:
            for i in l:
                print(i, "", end='')
            print()


# Test d = 6 -  ERROR
# Test d = 9 -  OK

if __name__ == '__main__':
    IMAGE_FILE_NAME: str = 'test.png'
    wrapper = ShapeWrapper(IMAGE_FILE_NAME)
    wrapper.Test()

    # print(wrapper.getDiameter())
    # print(wrapper.getCircleColor())
    # print(ShapeWrapper.hue2rgb1(64))
    # print(wrapper.getCircleColor() == ShapeWrapper.hue2rgb1(64))
