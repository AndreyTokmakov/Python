import urllib.request
import tensorflow as tf
import numpy as np
from keras import Model
from keras.optimizer_v2.rmsprop import RMSprop
from tensorflow import keras
from tensorflow.keras.applications.inception_v3 import InceptionV3

if __name__ == '__main__':
    weights_url = "https://storage.googleapis.com/mledu-datasets/inception_v3_weights_tf_dim_ordering_tf_kernels_notop.h5"
    weights_file = "inception_v3.h5"
    urllib.request.urlretrieve(weights_url, weights_file)
    pre_trained_model = InceptionV3(input_shape=(150, 150, 3),
                                    include_top=False,
                                    weights=None)
    pre_trained_model.load_weights(weights_file)

    print(pre_trained_model.summary())

    # Next, we’ll freeze the entire network from retraining and then set a variable to point
    # at mixed7’s output as where we want to crop the network up to.
    for layer in pre_trained_model.layers:
        layer.trainable = False

    last_layer = pre_trained_model.get_layer('mixed7')

    # print the output shape of the last layer,
    print('last layer output shape: ', last_layer.output_shape)

    last_output = last_layer.output

    ''' Let’s add our dense layers underneath this:'''
    # Flatten the output layer to 1 dimension
    x = keras.layers.Flatten()(last_output)

    # Add a fully connected layer with 1,024 hidden units and ReLU activation
    x = keras.layers.Dense(1024, activation='relu')(x)

    # Add a final sigmoid layer for classification
    x = keras.layers.Dense(1, activation='sigmoid')(x)

    # Now we can define our model simply by saying it’s our pretrained model’s input followed
    # by the x we just defined.

    model = Model(pre_trained_model.input, x)
    model.compile(optimizer=RMSprop(learning_rate=0.0001),
                  loss='binary_crossentropy',
                  metrics=['acc'])

    # NEED TO TRAIN MODEL

    '''
    history = model.fit_generator(train_generator,
                                  epochs=15,
                                  validation_data=validation_generator)
    '''