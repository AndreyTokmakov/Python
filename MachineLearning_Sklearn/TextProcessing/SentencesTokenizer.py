
from nltk.tokenize import sent_tokenize

if __name__ == '__main__':
    # Create text
    string = """Today's science is tomorrow's technology.
                Tomorrow starts today."""

    sentences = sent_tokenize(string)
    print(sentences)

