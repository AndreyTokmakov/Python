# TensorFlow and tf.keras
import tensorflow as tf

# Helper libraries
import numpy as np
import matplotlib.pyplot as plt


class myCallback(tf.keras.callbacks.Callback):
    def on_epoch_end(self, epoch, logs={}):
        if logs.get('accuracy') > 0.95:
            print("\nReached 95% accuracy so cancelling training!")
            self.model.stop_training = True


if __name__ == '__main__':
    print(f'Using TensofFlow {tf.__version__}')

    fashionMnist = tf.keras.datasets.fashion_mnist
    (train_images, train_labels), (test_images, test_labels) = fashionMnist.load_data()
    classNames = ['T-shirt/top', 'Trouser', 'Pullover', 'Dress', 'Coat', 'Sandal', 'Shirt', 'Sneaker', 'Bag',
                  'Ankle boot']

    # We can explore the format of the dataset before training the model.  
    # print(f"Traing data:\n   Images: {trainImages.shape}")
    # print(f"   Labels: {trainLabels}")

    # inspect the first image in the training set
    '''
    plt.figure()
    plt.imshow(trainImages[0])
    plt.colorbar()
    plt.grid(False)
    plt.show()
    '''

    train_images = train_images / 255.0
    test_images = test_images / 255.0

    #  display the first 25 images from the training set and display the class name below each image.
    '''
    plt.figure(figsize=(10, 10))
    for i in range(25):
        plt.subplot(5, 5, i + 1)
        plt.xticks([])
        plt.yticks([])
        plt.grid(False)
        plt.imshow(training_images[i], cmap=plt.cm.binary)
        plt.xlabel(classNames[train_labels[i]])
    plt.show()
    '''

    # Build the model --> Set up the layers
    model = tf.keras.Sequential([
        tf.keras.layers.Flatten(input_shape=(28, 28)),
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.Dense(10, activation=tf.nn.softmax)
    ])

    # Compile the model
    model.compile(optimizer='adam',
                  loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
                  metrics=['accuracy'])

    # Train the model
    callbacks = myCallback()
    model.fit(train_images, train_labels, epochs=50, callbacks=[callbacks])

    testLoss, testAccuracy = model.evaluate(train_images, train_labels, verbose=2)
    print(f'Test accuracy: {testAccuracy}')

    probabilityModel = tf.keras.Sequential([
        model, tf.keras.layers.Softmax()
    ])

    predictions = probabilityModel.predict(test_images)
    print(f'Predictions: {predictions[0]}')
    print(f'Predictions: {train_labels[0]}')
    # print(f'Predictions max: {np.argmax(predictions[0])}')
