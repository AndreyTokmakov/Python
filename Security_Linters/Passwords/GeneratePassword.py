import random
import string


def create_password(WPA=False):
    if WPA:
        characters: str = string.ascii_letters + string.digits
    else:  # WEP
        characters: str = string.digits
    return ''.join(random.choice(characters) for i in range(10))


if __name__ == '__main__':
    print(create_password(True))
