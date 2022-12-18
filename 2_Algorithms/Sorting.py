
def selection_sort(lst):
    # Traverse through all lst elements
    for i in range(len(lst)):
        # Find the minimum element in unsorted lst
        min_index = i
        for j in range(i + 1, len(lst)):
            if lst[min_index] > lst[j]:
                min_index = j

        # Swap the found minimum element with the first element
        lst[i], lst[min_index] = lst[min_index], lst[i]


def SelectionSort() -> None:

    lst = [3, 2, 1, 5, 4]
    selection_sort(lst)  # Calling selection sort function

    # Printing Sorted lst
    print("Sorted lst: ", lst)

# -------------------------------------------------------------------------------------------

def insertion_sort(list):
    # Traverse through 1 to len(lst)
    for i in range(1, len(list)):
        key = list[i]

        # Move elements of lst greater than key, to one position ahead
        j = i - 1
        while j >= 0 and key < list[j]:
            list[j + 1] = list[j]
            j -= 1
        list[j + 1] = key


# Driver code to test above
def InsertionSort() -> None:
    lst = [3, 2, 1, 5, 4]
    insertion_sort(lst)  # Calling insertion sort function

    print("Sorted list is: ", lst)

# -------------------------------------------------------------------------------------------


if __name__ == '__main__':
    # SelectionSort()
    InsertionSort()