
from nltk.corpus import gutenberg

# INFO: https://www.nltk.org/book/ch02.html

if __name__ == '__main__':
    # nltk.download('gutenberg')

    ids = gutenberg.fileids()
    print(ids, '\n')

    emma = gutenberg.words('austen-emma.txt')
    print(emma, '\n')

    for fileid in gutenberg.fileids():
        num_chars = len(gutenberg.raw(fileid))
        num_words = len(gutenberg.words(fileid))
        num_sents = len(gutenberg.sents(fileid))
        num_vocab = len(set(w.lower() for w in gutenberg.words(fileid)))
        print(round(num_chars/num_words), round(num_words/num_sents), round(num_words/num_vocab), fileid)