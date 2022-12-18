
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

def getKeyFromDictByValue(words: dict, value: int) -> str:
    for k,v in words.items():
        if (value == v):
            return k;
    return None

def Test_Learn_and_Classify():
    sentences = [
        'I love my dog',
        'I love my cat',
        'You love my dog!',
        'Do you think my dog is amazing?'
    ]

    tokenizer = Tokenizer(num_words=100)
    tokenizer.fit_on_texts(sentences)

    word_index = tokenizer.word_index
    sequences = tokenizer.texts_to_sequences(sentences)

    print("Word Index : ", word_index)
    print("Sequences  : ", sequences)

    # Try with words that the tokenizer wasn't fit to
    test_data = [
        'i really love my dog',
        'my dog loves my manatee'
    ]

    test_seq = tokenizer.texts_to_sequences(test_data)
    print("\nTest Sequence = ", test_seq)

    # Parse 'test_seq' by getting keys from 'word_index'
    print("Result: ", end='')
    for singleSentence in test_seq:
        print("[", end='');
        for wordId in singleSentence:
            k = getKeyFromDictByValue(word_index, wordId)
            print(f'{k} ', end='')
        print("]", end='] ');
    print("\n")

    # As the result we have [i love my dog ]] [my dog my ]]  since in learning data 'sentences'
    # we have no word 'really'

def Test_Learn_and_Classify_OOV():
    sentences = [
        'I love my dog',
        'I love my cat',
        'You love my dog!',
        'Do you think my dog is amazing?'
    ]

    tokenizer = Tokenizer(num_words=100, oov_token="<OOV>")
    tokenizer.fit_on_texts(sentences)

    word_index = tokenizer.word_index
    sequences = tokenizer.texts_to_sequences(sentences)

    print("Word Index : ", word_index)
    print("Sequences  : ", sequences)

    # Try with words that the tokenizer wasn't fit to
    test_data = [
        'i really love my dog',
        'my dog loves my manatee'
    ]

    test_seq = tokenizer.texts_to_sequences(test_data)
    print("\nTest Sequence = ", test_seq)

    # Parse 'test_seq' by getting keys from 'word_index'
    print("Result: ", end='')
    for singleSentence in test_seq:
        print("[", end='');
        for wordId in singleSentence:
            k = getKeyFromDictByValue(word_index, wordId)
            print(f'{k} ', end='')
        print("]", end='] ');
    print("\n")

    # As the result we have [i <OOV> love my dog ]] [my dog <OOV> my <OOV> ]]   since in learning data 'sentences'
    # we have no word 'really'
    # BUT here we have OOV instead of words we do not know yet

def Test_Learn_and_Classify_OOV_Padded():
    sentences = [
        'I love my dog',
        'I love my cat',
        'You love my dog!',
        'Do you think my dog is amazing?'
    ]

    tokenizer = Tokenizer(num_words = 100, oov_token="<OOV>")
    tokenizer.fit_on_texts(sentences)
    word_index = tokenizer.word_index
    sequences  = tokenizer.texts_to_sequences(sentences)

    padded = pad_sequences(sequences, maxlen=5)
    print("Word Index       : ", word_index)
    print("Sequences        : ", sequences)
    print("Padded Sequences : ", padded)

    # Try with words that the tokenizer wasn't fit to
    test_data = [
        'i really love my dog',
        'my dog loves my manatee'
    ]

    test_seq = tokenizer.texts_to_sequences(test_data)
    padded = pad_sequences(test_seq, maxlen=10)

    print("Test Sequence       : ", test_seq)
    print("Padded Test Sequence: ", padded)

if __name__ == '__main__':

    # Test_Learn_and_Classify()
    # Test_Learn_and_Classify_OOV();
    Test_Learn_and_Classify_OOV_Padded();
