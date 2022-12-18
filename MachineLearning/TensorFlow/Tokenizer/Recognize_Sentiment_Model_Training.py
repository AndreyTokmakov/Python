import json
from typing import Dict
import numpy as np
import tensorflow as tf
import matplotlib.pyplot as pyplot

from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

EMBEDDING_DIM = 16
VOCAB_SIZE = 10000
TRAINING_SIZE = 20000
MAX_LENGTH = 100
TRUNC_TYPE='post'
PADDING_TYPE='post'
OOV_TOKEN = "<OOV>"

with open("C:\\Projects\\Python_IDEA\\MachineLearning\\Data\\sarcasm.json", 'r') as f:
     datastore = json.load(f)

def ClassifyWords():
    sentences = []
    labels = []
    urls = []

    for item in datastore:
        sentences.append(item['headline'])
        labels.append(item['is_sarcastic'])
        urls.append(item['article_link'])

    tokenizer = Tokenizer(oov_token="<OOV>")
    tokenizer.fit_on_texts(sentences)

    sequences = tokenizer.texts_to_sequences(sentences)
    padded = pad_sequences(sequences, padding='post')

    # print(tokenizer.word_index) ''' All words tokens '''
    print(padded[0])
    print(padded.shape)


def Tokenizer_Fit_The_Learn_Data_Only():
    sentences = []
    labels = []
    urls = []
    for item in datastore:
        sentences.append(item['headline'])
        labels.append(item['is_sarcastic'])
        urls.append(item['article_link'])

    training_sentences = sentences[0:TRAINING_SIZE]
    testing_sentences = sentences[TRAINING_SIZE:]
    training_labels = labels[0:TRAINING_SIZE]
    testing_labels = labels[TRAINING_SIZE:]

    tokenizer = Tokenizer(num_words=VOCAB_SIZE, oov_token=OOV_TOKEN)
    tokenizer.fit_on_texts(training_sentences)

    word_index = tokenizer.word_index

    # Create 'TRAINING' sequences and pad them
    training_sequences = tokenizer.texts_to_sequences(training_sentences)
    training_padded = pad_sequences(training_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Create 'TESTING' sequences and pad them
    testing_sequences = tokenizer.texts_to_sequences(testing_sentences)
    testing_padded = pad_sequences(testing_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)


def Learn_on_TestData():
    sentences = []
    labels = []
    urls = []
    for item in datastore:
        sentences.append(item['headline'])
        labels.append(item['is_sarcastic'])
        urls.append(item['article_link'])

    training_sentences = sentences[0:TRAINING_SIZE]
    testing_sentences = sentences[TRAINING_SIZE:]
    training_labels = labels[0:TRAINING_SIZE]
    testing_labels = labels[TRAINING_SIZE:]

    tokenizer = Tokenizer(num_words=VOCAB_SIZE, oov_token=OOV_TOKEN)
    tokenizer.fit_on_texts(training_sentences)

    word_index = tokenizer.word_index

    # Create 'TRAINING' sequences and pad them
    training_sequences = tokenizer.texts_to_sequences(training_sentences)
    training_padded = pad_sequences(training_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Create 'TESTING' sequences and pad them
    testing_sequences = tokenizer.texts_to_sequences(testing_sentences)
    testing_padded = pad_sequences(testing_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Need to convert to NUMPY to work with KERAS
    training_padded = np.array(training_padded)
    training_labels = np.array(training_labels)
    testing_padded = np.array(testing_padded)
    testing_labels = np.array(testing_labels)

    # We create a neural network where we do the following at successive levels
    # 1. Every word will be learned epoch by epoch
    model = tf.keras.Sequential([
        tf.keras.layers.Embedding(VOCAB_SIZE, EMBEDDING_DIM, input_length=MAX_LENGTH),
        tf.keras.layers.GlobalAveragePooling1D(),
        tf.keras.layers.Dense(24, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    print(model.summary())

    num_epochs = 30
    history = model.fit(training_padded,
                        training_labels,
                        epochs=num_epochs,
                        validation_data=(testing_padded, testing_labels),
                        verbose=2)


def Learn_on_TestData_DrawGraphs():
    sentences = []
    labels = []
    urls = []
    for item in datastore:
        sentences.append(item['headline'])
        labels.append(item['is_sarcastic'])
        urls.append(item['article_link'])

    training_sentences = sentences[0:TRAINING_SIZE]
    testing_sentences = sentences[TRAINING_SIZE:]
    training_labels = labels[0:TRAINING_SIZE]
    testing_labels = labels[TRAINING_SIZE:]

    tokenizer = Tokenizer(num_words=VOCAB_SIZE, oov_token=OOV_TOKEN)
    tokenizer.fit_on_texts(training_sentences)

    word_index = tokenizer.word_index

    # Create 'TRAINING' sequences and pad them
    training_sequences = tokenizer.texts_to_sequences(training_sentences)
    training_padded = pad_sequences(training_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Create 'TESTING' sequences and pad them
    testing_sequences = tokenizer.texts_to_sequences(testing_sentences)
    testing_padded = pad_sequences(testing_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Need to convert to NUMPY to work with KERAS
    training_padded = np.array(training_padded)
    training_labels = np.array(training_labels)
    testing_padded = np.array(testing_padded)
    testing_labels = np.array(testing_labels)

    # We create a neural network where we do the following at successive levels
    # 1. Every word will be learned epoch by epoch
    model = tf.keras.Sequential([
        tf.keras.layers.Embedding(VOCAB_SIZE, EMBEDDING_DIM, input_length=MAX_LENGTH),
        tf.keras.layers.GlobalAveragePooling1D(),
        tf.keras.layers.Dense(24, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    print(model.summary())

    num_epochs = 30
    history = model.fit(training_padded,
                        training_labels,
                        epochs=num_epochs,
                        validation_data=(testing_padded, testing_labels),
                        verbose=2)

    def plot_graphs(history, string):
        pyplot.plot(history.history[string])
        pyplot.plot(history.history['val_'+string])
        pyplot.xlabel("Epochs")
        pyplot.ylabel(string)
        pyplot.legend([string, 'val_'+string])
        pyplot.show()

    plot_graphs(history, "accuracy")
    plot_graphs(history, "loss")

def Learn_on_TestData_and_TryTest():
    sentences = []
    labels = []
    urls = []
    for item in datastore:
        sentences.append(item['headline'])
        labels.append(item['is_sarcastic'])
        urls.append(item['article_link'])

    training_sentences = sentences[0:TRAINING_SIZE]
    testing_sentences = sentences[TRAINING_SIZE:]
    training_labels = labels[0:TRAINING_SIZE]
    testing_labels = labels[TRAINING_SIZE:]

    tokenizer = Tokenizer(num_words=VOCAB_SIZE, oov_token=OOV_TOKEN)
    tokenizer.fit_on_texts(training_sentences)

    word_index = tokenizer.word_index

    # Create 'TRAINING' sequences and pad them
    training_sequences = tokenizer.texts_to_sequences(training_sentences)
    training_padded = pad_sequences(training_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Create 'TESTING' sequences and pad them
    testing_sequences = tokenizer.texts_to_sequences(testing_sentences)
    testing_padded = pad_sequences(testing_sequences, maxlen=MAX_LENGTH, padding=PADDING_TYPE, truncating=TRUNC_TYPE)

    # Need to convert to NUMPY to work with KERAS
    training_padded = np.array(training_padded)
    training_labels = np.array(training_labels)
    testing_padded = np.array(testing_padded)
    testing_labels = np.array(testing_labels)

    # We create a neural network where we do the following at successive levels
    # 1. Every word will be learned epoch by epoch
    model = tf.keras.Sequential([
        tf.keras.layers.Embedding(VOCAB_SIZE, EMBEDDING_DIM, input_length=MAX_LENGTH),
        tf.keras.layers.GlobalAveragePooling1D(),
        tf.keras.layers.Dense(24, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    print(model.summary())

    num_epochs = 30
    history = model.fit(training_padded,
                        training_labels,
                        epochs=num_epochs,
                        validation_data=(testing_padded, testing_labels),
                        verbose=2)

    sentence = [
        "granny starting to fear spiders in the garden might be real",
        "game of thrones season finale showing this sunday night"
    ]

    sequences = tokenizer.texts_to_sequences(sentence)
    padded = pad_sequences(sequences,
                           maxlen=MAX_LENGTH,
                           padding=PADDING_TYPE,
                           truncating=TRUNC_TYPE)
    print(model.predict(padded))



# Leasson: https://www.youtube.com/watch?v=Y_hzMnRXjhI&list=PLQY2H8rRoyvwLbzbnKJ59NkZvQAW9wLbx&index=11
if __name__ == '__main__':
    # ClassifyWords()
    # Tokenizer_Fit_The_Learn_Data_Only();
    # Learn_on_TestData()
    # Learn_on_TestData_DrawGraphs();
    Learn_on_TestData_and_TryTest();
