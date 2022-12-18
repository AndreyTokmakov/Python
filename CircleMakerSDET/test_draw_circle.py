import os
import pytest
import subprocess
from circlemaker import draw_image
from CircleWrapper import ShapeWrapper

IMAGE_PATH = 'test.png'
CIRCLE_MODULE_NAME = 'circlemaker.py'


class Utilities(object):

    @staticmethod
    def remove_silent(file_path: str) -> bool:
        try:
            os.remove(file_path)
            return True
        except Exception as exc:
            return False

    @staticmethod
    def is_file_exist(file_path: str) -> bool:
        return os.path.exists(file_path)

    @staticmethod
    def call_module(diam: int, hue: int, path: str):
        try:
            proc = subprocess.Popen(["python", CIRCLE_MODULE_NAME, "-d", str(diam), "-hue", str(hue), "-path", path],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    shell=False)
        except Exception as exc:
            raise exc

        proc.wait()
        return proc.poll()


class TestCallModuleErrorHandling(object):

    @pytest.fixture(autouse=True)
    def around_each_tests(self):
        Utilities.remove_silent(IMAGE_PATH)
        yield

    def test_diameter_negative(self):
        code = Utilities.call_module(-1, 128, IMAGE_PATH)
        assert 0 != code, "Module call shall not be successful"
        assert not Utilities.is_file_exist(IMAGE_PATH), "File shall not be created"

    def test_diameter_to_large(self):
        code = Utilities.call_module(401, 128, IMAGE_PATH)
        assert 0 != code, "Module call shall not be successful"
        assert not Utilities.is_file_exist(IMAGE_PATH), "File shall not be created"

    def test_hue_negative(self):
        code = Utilities.call_module(128, -1, IMAGE_PATH)
        assert 0 != code, "Module call shall not be successful"
        assert not Utilities.is_file_exist(IMAGE_PATH), "File shall not be created"

    def test_hue_to_large(self):
        code = Utilities.call_module(128, 361, IMAGE_PATH)
        assert 0 != code, "Module call shall not be successful"
        assert not Utilities.is_file_exist(IMAGE_PATH), "File shall not be created"


class TestCallModulePositive(object):

    @pytest.mark.parametrize("diameter, hue, path", [
        (1, 1, "path1.png"),
        (100, 32, "path2.png"),
        (200, 64, "path3.png"),
        (300, 96, "path4.png"),
        (350, 128, "path5.png"),
        (350, 256, "path6.png"),
        (350, 360, "path7.png"),
    ])
    def test_diameter_negative(self, diameter, hue, path):
        Utilities.remove_silent(path)
        code = Utilities.call_module(diameter, hue, path)
        assert 0 == code, "Module call shall be successful"
        assert Utilities.is_file_exist(path), "Image file should be created"
        wrapper = ShapeWrapper(path)
        assert wrapper.getDiameter() == diameter + 1
        assert wrapper.getCircleColor() == ShapeWrapper.hue2rgb(hue)
        Utilities.remove_silent(path)


# No module call - test 'draw_image' method only
class TestMethodCall(object):

    @pytest.fixture(autouse=True)
    def around_each_tests(self):
        Utilities.remove_silent(IMAGE_PATH)
        yield

    @pytest.mark.parametrize("diameter, hue, diameter_expected", [
        (0, 0, 0),
        (3, 11, 4),
        (5, 22, 6),
        (7, 33, 8),
        (9, 44, 10)
    ])
    def test_draw_image(self, diameter, hue, diameter_expected):
        draw_image(diameter, hue, IMAGE_PATH)
        wrapper = ShapeWrapper(IMAGE_PATH)
        os.remove(IMAGE_PATH)

        assert wrapper.getDiameter() == diameter_expected
        assert wrapper.getCircleColor() == ShapeWrapper.hue2rgb(hue)
