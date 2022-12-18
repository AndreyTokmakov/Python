import tensorflow as tf

from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.layers import Embedding, LSTM, Dense, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam

import matplotlib.pyplot as plt
import numpy

FILE_PATH = "S:\Projects\Python_IDEA\MachineLearning\Data\irish-lyrics-eof.txt"

fileLines = list()
with open(FILE_PATH) as file:
    for line_terminated in file:
        line = line_terminated.rstrip('\n')
        fileLines.append(line);

'''
По факту в этом примере мы
1. читаем файл построчно
2. потом каждую сторку Token-изируем
3. Подготавливаем данные так что бы каждая строка была представлена в виде
    - слово1 слово2 --> результат (слово3)
    - слово1 слово2 слово3 --> результат (слово4)
    - слово1 слово2 слово3 слово4--> результат (слово5)
4. Этот массив переводим в массив NumPy
5. Обучаемся на нем на 100 эпохах
6. Пробуем пспрогнозировать следующие 100 строк для входной строки "I've got a bad feeling about this"
'''

# LESSON: https://www.youtube.com/watch?v=ZMudJXhsUpY&list=PLQY2H8rRoyvwLbzbnKJ59NkZvQAW9wLbx&index=13
if __name__ == '__main__':

    tokenizer = Tokenizer(num_words=100)
    tokenizer.fit_on_texts(fileLines)
    wordsIndices = tokenizer.word_index

    wordsCount = len(wordsIndices) + 1;
    print(f"{wordsCount} words read from file.")

    inputSequences = []
    for line in fileLines:
        # Get tokens for each line
        tokenList = tokenizer.texts_to_sequences([line])[0]
        for i in range(1, len(tokenList)):
            nGramSequence = tokenList[:i + 1]
            inputSequences.append(nGramSequence)

    maxSequenceLength = max([len(x) for x in inputSequences])
    # print(maxSequenceLength)

    inputSequences = numpy.array(pad_sequences(inputSequences,
                                               maxlen=maxSequenceLength,
                                               padding='pre'))
    xs = inputSequences[:, :-1]
    labels = inputSequences[:, -1]

    ''' For example, is
    inputSequences:   [[ 0  0  0 ...  0 51 12], [ 0  0  0 ... 51 12 96], [ 0  0  0 ... 12 96 48],...]
    xs --->           [[ 0  0  0 ...  0 51],  [ 0  0  0 ... 51 12 ], [ 0  0  0 ... 12 96],...]
    labels --->       [[12], [96], [48],...]
    '''

    ys = tf.keras.utils.to_categorical(labels, num_classes=wordsCount)

    model = Sequential()
    model.add(Embedding(wordsCount, 100, input_length=maxSequenceLength - 1))
    model.add(Bidirectional(LSTM(150)))
    model.add(Dense(wordsCount, activation='softmax'))
    adam = Adam(lr=0.01)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    history = model.fit(xs, ys, epochs=20, verbose=1)
    print(model)

    seed_text = "I've got a bad feeling about this"
    next_words = 100

    for _ in range(next_words):
        token_list = tokenizer.texts_to_sequences([seed_text])[0]
        token_list = pad_sequences([token_list], maxlen=maxSequenceLength - 1, padding='pre')

        # predicted = model.predict(token_list, verbose=0)
        predicted = model.predict(token_list, verbose=0)
        predicted_classes = numpy.argmax(predicted, axis=1)


        output_word = ""
        for word, index in tokenizer.word_index.items():
            if index == predicted_classes:
                output_word = word
                break
        seed_text += " " + output_word
    print(seed_text)
