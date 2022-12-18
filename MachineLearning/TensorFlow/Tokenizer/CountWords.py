
from tensorflow.keras.preprocessing.text import Tokenizer

if __name__ == '__main__':
    sentences = [
        'i love my dog',
        'I, love my cat',
        'You love my dog!'
    ]

    tokenizer = Tokenizer(num_words = 100)
    tokenizer.fit_on_texts(sentences)
    word_index = tokenizer.word_index

    
    print(word_index)