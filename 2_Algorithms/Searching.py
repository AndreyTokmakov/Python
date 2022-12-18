def linear_search(list, key):
    if len(list) <= 0:  # Sanity check
        return -1

    for i in range(len(list)):
        if list[i] == key:
            return i  # If found return index
    return -1  # Return -1 otherwise


def LinearSearch():
    lst = [5, 4, 1, 0, 5, 95, 4, -100, 200, 0]
    key = 95

    index = linear_search(lst, key)
    if index != -1:
        print("Key:", key, "is found at index:", index)
    else:
        print(key, " is not found in the list.")


# -------------------------------------------------------------------------------------------

def binary_search(lst, left, right, key):
    while left <= right:
        mid = left + (right - left) // 2
        if lst[mid] == key:  # Check if key is present at mid
            return mid
        elif lst[mid] < key:  # If key is greater, ignore left half
            left = mid + 1
        else:  # If key is smaller, ignore right half
            right = mid - 1
    # If we reach here, then the element was not present
    return -1


def BinarySearch():
    lst = [1, 2, 3, 10, 20, 40, 111, 244, 14444, 800000]
    key = 111

    # Function call
    result = binary_search(lst, 0, len(lst) - 1, key)
    if result != -1:
        print(f'Element {key} is present at index {result}')
    else:
        print(f'Element {key}  is not present in the list')


# -------------------------------------------------------------------------------------------


if __name__ == '__main__':
    # LinearSearch()
    BinarySearch()
