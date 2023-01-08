
class MyClass:
    # Return the resource to default setting
    def __init__(self):
        self.setting = None

    def reset(self):
        self.setting = 0


class ObjectPool:

    def __init__(self, initial_size):
        self.__size = initial_size
        self.objects = [MyClass() for _ in range(self.__size)]

    def acquire(self):
        if not self.objects:
            print("Extend")
            self.objects = [MyClass() for _ in range(self.__size)]
        return self.objects.pop()

    def release(self, obj: MyClass):
        obj.reset()
        self.objects.append(obj)

    @property
    def size(self) -> int:
        return len(self.objects)


def test1():
    pool = ObjectPool(3)

    reusable = pool.acquire()
    print(pool.size)

    pool.release(reusable)
    print(pool.size)


def test2():
    pool = ObjectPool(3)
    for _ in range(5):
        reusable = pool.acquire()
        print(pool.size)


if __name__ == "__main__":
    # test1()
    test2()