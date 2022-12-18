import tensorflow as tf
mnist = tf.keras.datasets.mnist

if __name__ == '__main__':

    (x_train, y_train),(x_test, y_test) = mnist.load_data()
    x_train, x_test = x_train / 255.0, x_test / 255.0

    model = tf.keras.models.Sequential([
        tf.keras.layers.Flatten(input_shape=(28, 28)),
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(10, activation='softmax')
    ])

    ''' The losses.SparseCategoricalCrossentropy loss takes a vector of logits and a True index and returns a scalar loss for each example. '''
    lossFunc = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True)


    model.compile(optimizer = 'adam',
                  loss = lossFunc,
                  metrics = ['accuracy'])

    ''' The Model.fit method adjusts the model parameters to minimize the loss: '''
    model.fit(x_train, y_train, epochs = 5)

    ''' The Model.evaluate method checks the models performance, usually on a "Validation-set" or "Test-set". '''
    model.evaluate(x_test,  y_test, verbose = 2)

    predictions = model(x_train[:1]).numpy()
    print(predictions)