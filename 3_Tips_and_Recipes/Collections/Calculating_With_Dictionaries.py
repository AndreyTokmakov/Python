

""" Problem
You want to perform various calculations (e.g., minimum value, maximum value, sort‐
ing, etc.) on a dictionary of data.
"""

def Get_Max_Min_Simple():
    prices = {
        'ACME': 45.23,
        'AAPL': 612.78,
        'IBM': 205.55,
        'HPQ': 37.20,
        'FB': 10.75
    }

    min_price = min(zip(prices.values(), prices.keys()))
    max_price = max(zip(prices.values(), prices.keys()))

    print("min_price: ", min_price)
    print("max_price: ", max_price)


def Get_Max_Min_LambdaWithKey():
    prices = {
        'ACME': 45.23,
        'AAPL': 612.78,
        'IBM': 205.55,
        'HPQ': 37.20,
        'FB': 10.75
    }

    min_price = min(prices, key=lambda k: prices[k])  # Returns 'FB'
    max_price = max(prices, key=lambda k: prices[k])  # Returns 'AAPL'

    print(min_price, max_price)


if __name__ == '__main__':
    Get_Max_Min_Simple()
    # Get_Max_Min_LambdaWithKey()