from typing import Optional


def try_to_print(some_value: Optional[int]):
    if some_value:
        print(some_value)
    else:
        print("Value is not specified")


if __name__ == '__main__':
    try_to_print(None)
    try_to_print(1)
