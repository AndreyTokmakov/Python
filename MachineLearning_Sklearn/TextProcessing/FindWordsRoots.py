
from nltk.stem.porter import PorterStemmer

# Lexemized words are given, which need to be converted into their root forms.
if __name__ == '__main__':
    tokenized_words = ['i ', 'am', 'humbled', 'by', 'this', 'traditional', 'meeting']

    porter = PorterStemmer()

    res = [porter.stem(word) for word in tokenized_words]
    print(res)