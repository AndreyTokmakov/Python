
import nltk
from nltk.tokenize import word_tokenize

if __name__ == '__main__':
    # Create text
    string = "Today's science is tomorrow's technology"

    tokens = word_tokenize(string)
    print(tokens)

