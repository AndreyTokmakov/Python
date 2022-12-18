import collections


def average_words_length(sentence):
    for p in "!?',;.":
        sentence = sentence.replace(p, '')
    words = sentence.split()
    return round(sum(len(word) for word in words) / len(words), 2)


def average_words_length1(sentence):
    for p in "!?',;.":
        sentence = sentence.replace(p, '')
    words = sentence.split()
    # return round(sum(len(word) for word in words)/len(words), 2)
    count, len_total = 0, 0
    for w in words:
        len_total += len(w)
        count += 1
    return len_total / count


def Average_Words_Length():
    sentence1 = "Hi all, my name is Tom...I am originally from Australia."
    sentence2 = "I need to work very hard to learn more about algorithms in Python!"

    print(average_words_length(sentence1), average_words_length1(sentence1))
    print(average_words_length(sentence2), average_words_length1(sentence2))


# -------------------------------------------------------------------------------------------

def first_unique_character(text: str):
    frequency = {}
    for c in text:
        count: int = frequency.get(c, 0)
        frequency[c] = count + 1
    for c in text:
        if 1 == frequency.get(c, 0):
            return c
    return '\0'


def first_unique_character2(text: str):
    frequency = collections.Counter(text)
    for c in text:
        if 1 == frequency.get(c, 0):
            return c
    return '\0'


def First_Unique_Character():
    print(first_unique_character('abcbc'), first_unique_character2('abcbc'))
    print(first_unique_character('abacbxc'), first_unique_character2('abacbxc'))


# -------------------------------------------------------------------------------------------

def is_palindrome(text: str) -> bool:
    length: int = int(len(text))
    for i in range(0, int(length / 2)):
        if text[i] != text[length - 1 - i]:
            return False
    return True


def is_palindrome_PyStyle(text: str) -> bool:
    return text == text[::-1]


def isPalindrome() -> None:
    print(is_palindrome('abcba'), is_palindrome_PyStyle('abcba'))
    print(is_palindrome('abccba'), is_palindrome_PyStyle('abccba'))
    print(is_palindrome('abcdba'), is_palindrome_PyStyle('abcdba'))
    print(is_palindrome('abcdcba'), is_palindrome_PyStyle('abcdcba'))


# -------------------------------------------------------------------------------------------

def move_zeros_to_end(nums):
    for i in nums:
        if 0 in nums:
            nums.remove(0)
            nums.append(0)
    return nums


def move_zeros_to_end2(nums):
    pos: int = 0
    for i in range(0, len(nums)):
        if 0 != nums[i]:
            nums[pos], nums[i] = nums[i], nums[pos]
            pos += 1


def MoveZerosToEnd():
    array1 = [0, 1, 0, 3, 12]
    array2 = [1, 7, 0, 0, 8, 0, 10, 12, 0, 4]

    move_zeros_to_end2(array1)
    move_zeros_to_end2(array2)

    print(array1)
    print(array2)

# -------------------------------------------------------------------------------------------


def Capitalize_Name():
    name: str = "alister krawly"
    capitalized = ' '.join([n.capitalize() for n in name.split(' ')])

    print(capitalized)


# -------------------------------------------------------------------------------------------


def Count_Substring():
    origin: str = "ABC__AB_ABC"
    s: str = "ABC"

    pos, count, length = 0, 0, len(s)
    while True:
        pos = origin.find(s, pos)
        if -1 == pos:
            break
        else:
            pos += length
            count += 1

    print(count)



# -------------------------------------------------------------------------------------------

def PrintSubStringWithOneChar():
    s = 'abcbe'
    for i in range(len(s)):
        t = s[:i] + s[i + 1:]
        print(t)


if __name__ == '__main__':
    # Average_Words_Length()
    # First_Unique_Character()
    # isPalindrome()
    # PrintSubStringWithOneChar()
    MoveZerosToEnd()
    # Capitalize_Name()
    # Count_Substring()