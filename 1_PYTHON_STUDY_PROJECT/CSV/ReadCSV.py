
import csv
from typing import List

DATA_FILE = "./data/shmya_final_version.csv"

if __name__ == '__main__':

    rows: List = []
    with open(DATA_FILE, newline='') as File:
        reader = csv.reader(File)
        for row in reader:
            rows.append(row)

    rows.pop(0)

    sum_total, count = 0, 0
    for row in rows:
        date = row[0]
        if '2022-01-01' in date:
            count += 1
            sum_total += int(row[3])

    print(sum_total/count)



