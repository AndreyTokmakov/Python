from nltk.corpus import stopwords


def init():
    import nltk
    nltk.download('stopwords')


if __name__ == '__main__':
    # init()

    tokenized_words = ['i',
                       'am',
                       'going',
                       'to',
                       'go',
                       'to',
                       'the',
                       'store',
                       'and',
                       'park']

    stop_words = stopwords.words('english')
    # print(stop_words)

    # delete all stop words
    tokenized_words_new = [word for word in tokenized_words if word not in stop_words]

    print(tokenized_words_new)