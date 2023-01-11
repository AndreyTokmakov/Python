

class Holder(object):

    def __init__(self):
        self.__password: str = "qwerty"

    def __str__(self) -> str:
        return f'Holder(password=\'********\')'

    def __repr__(self) -> str:
        return str(self)

    def get_password(self) -> str:
        return self.__password


if __name__ == '__main__':
    h: Holder = Holder()
    print(h)

    print("HACK to access private field: ", h._Holder__password)

    print(h.get_password())
    h._Holder__password = 'qwerty_UPDATED'
    print(h.get_password())