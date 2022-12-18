
def slice_tests():
    strings = ["one", "two", "three", "four", "five", "six", "seven"]

    print("[1:3] = ", strings[1:3])
    print("[:3]  = ", strings[:3])
    print("[1:] = ", strings[1:])
    print("[3:]  = ", strings[3:])
    print("[::3] = ", strings[::3])
    print("[:-3] = ", strings[:-3])


if __name__ == '__main__':
    slice_tests()