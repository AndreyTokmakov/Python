
class Holder(object):

    def __init__(self):
        self.value: int = 100

    def __str__(self) -> str:
        return f'Holder({self.value})'

    def __repr__(self) -> str:
        return str(self)


if __name__ == "__main__":
    holder: Holder = Holder()

    print(holder)
    holder.__dict__['value'] = 123

    # Holder.__dict__['value'].__set__(holder, 40)

    print(holder.__dict__)

