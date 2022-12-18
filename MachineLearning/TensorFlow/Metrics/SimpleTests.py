import tensorflow as tf
import tensorflow_hub as hub

if __name__ == '__main__':

    model = hub.KerasLayer("https://tfhub.dev/google/nnlm-en-dim128/2")
    embeddings = model(["The rain in Spain.", "falls", "mainly", "In the plain!"])

    print(embeddings.shape)  #(4,128)