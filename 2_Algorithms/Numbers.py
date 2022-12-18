def _reverse_number(num: int) -> int:
    result: int = 0
    while num:
        result = result * 10 + num % 10
        num = int(num / 10)
    return result


def Reverse_Number():
    print(f'123 = {_reverse_number(123)}')


# -------------------------------------------------------------------------------------------

def is_monotonic_array(nums) -> bool:
    return (all(nums[i] <= nums[i + 1] for i in range(len(nums) - 1)) or
            all(nums[i] >= nums[i + 1] for i in range(len(nums) - 1)))


def is_monotonic_array2(nums) -> bool:
    if 0 == len(nums):
        return True
    increasing: bool = True if nums[-1] > nums[0] else False
    for i in range(1, len(nums)):
        if (nums[i] != nums[i - 1]) and increasing != (nums[i] >= nums[i - 1]):
            return False
    return True


# An array is monotonic if and only if it is monotone increasing, or monotone decreasing
def MonotonicArray() -> None:
    A = [6, 5, 4, 4]
    B = [1, 1, 1, 3, 3, 4, 3, 2, 4, 2]
    C = [1, 2, 2, 3]
    D = []

    print(is_monotonic_array(A), is_monotonic_array2(A))
    print(is_monotonic_array(B), is_monotonic_array2(B))
    print(is_monotonic_array(C), is_monotonic_array2(C))
    print(is_monotonic_array(D), is_monotonic_array2(D))


# ---------------------------------------- Knapsack ---------------------------------------------------

def solveKnapsack(weights, prices, capacity, index, memo):
    # base case of when we have run out of capacity or objects
    if capacity <= 0 or index >= len(weights):
        return 0
    if (capacity, index) in memo:  # check for solution in memo table
        return memo[(capacity, index)]

    # if weight at index-th position is greater than capacity, skip this object
    if weights[index] > capacity:
        # store result in memo table
        memo[(capacity, index)] = solveKnapsack(weights, prices, capacity, index + 1, memo)
        return memo[(capacity, index)]

        # recursive call, either we can include the index-th object or we cannot,
        # we check both possibilities and return the most optimal one using max
    memo[(capacity, index)] = max(prices[index] +
                                  solveKnapsack(weights, prices, capacity - weights[index], index + 1, memo),
                                  solveKnapsack(weights, prices, capacity, index + 1, memo))
    return memo[(capacity, index)]


def _knapsack(weights, prices, capacity):
    # create a memo dictionary
    memo = {}
    return solveKnapsack(weights, prices, capacity, 0, memo)


def Knapsack():
    print(_knapsack([2, 1, 1, 3], [2, 8, 1, 10], 4))


# ---------------------------------------- Knapsack ---------------------------------------------------

def countways(bills, amount, index: int = 0):
    if amount == 0:  # base case 1
        print(f'OK : {bills}, {amount}, {index}')
        return 1
    if amount < 0 or index >= len(bills):  # base case 2
        print(f'BAD: {bills}, {amount}, {index}')
        return 0

    print(f'{bills}, {amount}, {index}')

    # count the number of ways to make amount by including bills[index] and excluding bills[index]
    return countways(bills, amount - bills[index], index) + \
           countways(bills, amount, index + 1)


def CoinChangeProblem():
    result = countways([1, 2], 5)
    print(result)


# ------------------------------- Remove duplicates | Deduplicate ---------------------------------------------------

def dedup(items):
    seen = set()
    for entry in items:
        if entry not in seen:
            yield entry
            seen.add(entry)


def Deduplicate():
    a = [1, 5, 2, 1, 9, 1, 5, 10]
    print(list(dedup(a)))


if __name__ == '__main__':
    # Reverse_Number()
    # MonotonicArray()
    # Knapsack()
    # CoinChangeProblem()
    Deduplicate()
