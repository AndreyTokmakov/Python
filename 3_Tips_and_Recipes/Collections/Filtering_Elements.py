
src = [1, 4, -5, 10, -7, 2, 3, -1]
values = ['1', '2', '-3', '-', '4', 'N/A', '5']


def is_int(val):
    try:
        x = int(val)
        return True
    except ValueError:
        return False


if __name__ == '__main__':

    positives = [n for n in src if n > 0]
    print(positives)

    negatives = [n for n in src if n < 0]
    print(negatives)

    numbers = list(filter(is_int, values))
    print(numbers)
