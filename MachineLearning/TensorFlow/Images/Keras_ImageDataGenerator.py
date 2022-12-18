import urllib.request
import zipfile
import tensorflow as tf
import numpy as np
from keras.optimizer_v2.rmsprop import RMSprop
from tensorflow import keras
from tensorflow.keras.preprocessing.image import ImageDataGenerator

TRAINING_DIR = 'C:\\Projects\\TEST_DATA\\PYTHON\\horse-or-human\\training\\'
VALIDATION_DIR = 'C:\\Projects\\TEST_DATA\\PYTHON\\horse-or-human\\validation\\'


def DownloadData():
    url = "https://storage.googleapis.com/laurencemoroney-blog.appspot.com/horse-or-human.zip"
    file_name = "horse-or-human.zip"
    urllib.request.urlretrieve(url, file_name)
    zip_ref = zipfile.ZipFile(file_name, 'r')
    zip_ref.extractall(TRAINING_DIR)
    zip_ref.close()

    validation_url = "https://storage.googleapis.com/laurencemoroney-blog.appspot.com/validation-horse-or-human.zip"
    validation_file_name = "validation-horse-or-human.zip"
    urllib.request.urlretrieve(validation_url, validation_file_name)
    zip_ref = zipfile.ZipFile(validation_file_name, 'r')
    zip_ref.extractall(VALIDATION_DIR)
    zip_ref.close()


if __name__ == '__main__':
    ''' This simply downloads the ZIP of the training data and unzips it into a directory '''
    #  DownloadData();

    # We first create an instance of an ImageDataGenerator called train_datagen. We then
    # specify that this will generate images for the training process by flowing them from a
    # directory.
    # All images will be rescaled by 1./255
    train_datagen = ImageDataGenerator(rescale=1 / 255)
    train_generator = train_datagen.flow_from_directory(TRAINING_DIR,
                                                        target_size=(300, 300),
                                                        class_mode='binary')

    ''' up another ImageDataGenerator to manage these images:'''
    validation_datagen = ImageDataGenerator(rescale=1/255)
    validation_generator = train_datagen.flow_from_directory(VALIDATION_DIR,
                                                             target_size=(300, 300),
                                                             class_mode='binary')

    # There are a number of things to note here. First of all, this is the very first layer. We’re
    # defining 16 filters, each 3 × 3, but the input shape of the image is (300, 300, 3).
    # Remember that this is because our input image is 300 × 300 and it’s in color, so there
    # are three channels, instead of just one for the monochrome Fashion MNIST dataset
    # we were using earlier.
    model = tf.keras.models.Sequential([
        tf.keras.layers.Conv2D(16, (3, 3), activation='relu', input_shape=(300, 300, 3)),
        tf.keras.layers.MaxPooling2D(2, 2),
        tf.keras.layers.Conv2D(32, (3, 3), activation='relu'),
        tf.keras.layers.MaxPooling2D(2, 2),
        tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
        tf.keras.layers.MaxPooling2D(2, 2),
        tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
        tf.keras.layers.MaxPooling2D(2, 2),
        tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
        tf.keras.layers.MaxPooling2D(2, 2),
        tf.keras.layers.Flatten(),
        tf.keras.layers.Dense(512, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])

    # print(model.summary())

    ''' RMSprop - root mean square propagation '''
    model.compile(loss='binary_crossentropy',
                  optimizer=RMSprop(learning_rate=0.001),
                  metrics=['accuracy'])

    # We train by using fit_generator and passing it the training_generator we created earlier:
    history = model.fit_generator(train_generator,
                                  epochs=15,
                                  validation_data=validation_generator)
