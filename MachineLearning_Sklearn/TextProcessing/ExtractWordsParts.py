from nltk import pos_tag
from nltk import word_tokenize

if __name__ == '__main__':
    # import nltk
    # nltk.download('averaged_perceptron_tagger')

    text_data = "Chris loved outdoor running"
    text_tagged = pos_tag(word_tokenize(text_data))
    
    print(text_tagged, '\n')

    '''
    | NNP  |  Proper name, singular
    | NN   |  Noun, singular or uncountable
    | RB   |  Adverb
    | VBD  |  Verb, past tense
    | VBG  |  Verb, gerund, or present participle
    | JJ   |  Adjective
    | PRP  |  Personal Pronoun
    '''

    # Filer words: [get all nouns]
    filtered = [word for word, tag in text_tagged if tag in ['NN', 'NNS', 'NNP', 'NNPS']]
    print(filtered)
    

