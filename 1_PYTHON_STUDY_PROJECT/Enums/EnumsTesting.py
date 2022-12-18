from enum import Enum
from enum import IntEnum


class TargetType(Enum):
    UNDEFINED = 0;
    UNIT_TESTS = 1;
    BROWSER_TESTS = 2;
    PERFORMANCE_TESTS = 3;
    INSTALLER_PY_TESTS = 4;


class Color(Enum):
    RED = 1
    GREEN = 2
    BLUE = 3


class IntColor(IntEnum):
    RED = 1
    GREEN = 2
    BLUE = 3


def ColorTest():
    for color in Color:
        print(color)


def StringTypeToEnumTest():
    typeStr = "BROWSER_TESTS"
    type = TargetType.UNDEFINED
    try:
        type = TargetType[typeStr]
    except KeyError as exc:
        print("Failed to convert value '", typeStr, "' to TargetType object")

    print(type)


if __name__ == '__main__':
    # ColorTest()

    # StringTypeToEnumTest();

    print(IntColor.GREEN)
