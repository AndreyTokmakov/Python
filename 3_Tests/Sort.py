import random, typing

def sort_by_length():
    names = ['Socrates', 'Archimedes', 'Plato', 'Aristotle']
    names.sort(key=len)
    print(names)

n = 10 ** 4
data = [random.randint(1, 10 ** 9) for _ in range(n)]

def sort_local(n: int) -> None:
    data = [random.randint(1, 10 ** 9) for i in range(n)]
    for i in range(len(data)):
        for j in range(i, len(data)):
            if data[i] > data[j]:
                data[i], data[j] = data[j], data[i]

def sort_global(n: int) -> None:
    for i in range(n): data[i] = random.randint(1, 10 ** 9)
    for i in range(len(data)):
        for j in range(i, len(data)):
            if data[i] > data[j]:
                data[i], data[j] = data[j], data[i]

if __name__ == '__main__':
    # sort_by_length()
    print(n)

    pass