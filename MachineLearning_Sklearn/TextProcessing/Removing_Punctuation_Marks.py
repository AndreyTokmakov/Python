
import unicodedata
import sys

if __name__ == '__main__':
    # Create Text
    text_data = ['Hi!!!! I. Love. This. Song....', '100% Agree! !! ! #LoveIT', 'Right?!?!']

    # Create a punctuation dictionary
    punctuation = dict.fromkeys(i for i in range(sys.maxunicode) if unicodedata.category(chr(i)).startswith('P'))

    # Remove any punctuation marks in all string values
    result = [string.translate(punctuation) for string in text_data]
    print(result)
