
if __name__ == '__main__':

    values = ['one', 'two', 'three', 'four', 'five']
    values2 = ['I', 'II', 'III', 'IV', 'V']

    for a, b in zip(values, values2):
        print(f'{a} = {b}')
