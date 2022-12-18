import random

if __name__ == '__main__':
    print("Random tests.....")

    num = random.random()
    print(num)

    num = random.randint(0, 9)
    print(f"in range of 0 - 9 = {num}")

    num = random.randrange(0, 100, 5) # 5, 10, 15, 20 ... rand with step = 5
    print(num)

    color = random.choice(["red", "black", "green"])
    print(f'Random color = {color}')