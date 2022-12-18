import nltk
from sklearn.preprocessing import MultiLabelBinarizer
from nltk.tokenize import word_tokenize


# Более реалистичной является ситуация, когда есть данные, где каждое наблюдение
# содержит твит, и мы хотим преобразовать эти предложения в признаки отдельных
# частей речи (например, признак с 1, если присутствует собственное существительное,
# и 0 в противном случае):

if __name__ == '__main__':
    tweets = ["I am eating a burrito for breakfast",
              "Political science is an amazing field",
              "San Francisco is an awesome city"]

    tagged_tweets = []

    # Пометить каждое слово и каждый твит
    for tweet in tweets:
        tweet_tag = nltk.pos_tag(word_tokenize(tweet))
        tagged_tweets.append([tag for word, tag in tweet_tag])

    # Применить кодирование с одним активным состоянием, чтобы
    # конвертировать метки в признаки
    one_hot_multi = MultiLabelBinarizer()
    X = one_hot_multi.fit_transform(tagged_tweets)

    print(X, "\n")

    # Показать имена признаков
    print(one_hot_multi.classes_)