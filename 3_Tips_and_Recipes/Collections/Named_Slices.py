
if __name__ == '__main__':

    record = '...101...123...'

    print(int(record[3:6]), int(record[9:12]))

    FIRST_VAL, SECOND_VAL = slice(3, 6), slice(9, 12)

    print(int(record[FIRST_VAL]), int(record[SECOND_VAL]))