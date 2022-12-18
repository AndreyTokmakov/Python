import os
import pydot
import graphviz
import tensorflow as tf
import matplotlib.pyplot as plt

from tensorflow import keras
from tensorflow.keras import layers

# TODO: Example from here https://keras.io/examples/vision/image_classification_from_scratch/

DATA_DIR = 'S:\Projects\Python_IDEA\MachineLearning\Data'
PET_IMAGES_DIR = f'{DATA_DIR}\kagglecatsanddogs_3367a\PetImages'


def get_data():
    num_skipped = 0
    for folder_name in ("Cat", "Dog"):
        folder_path = os.path.join(PET_IMAGES_DIR, folder_name)
        for fname in os.listdir(folder_path):
            fpath = os.path.join(folder_path, fname)
            try:
                fobj = open(fpath, "rb")
                is_jfif = tf.compat.as_bytes("JFIF") in fobj.peek(10)
            finally:
                fobj.close()

            if not is_jfif:
                num_skipped += 1
                # Delete corrupted image
                os.remove(fpath)
    print("Deleted %d images" % num_skipped)


def get_dataset(image_size, batch_size):
    train_data = tf.keras.preprocessing.image_dataset_from_directory(
        PET_IMAGES_DIR,
        validation_split=0.2, subset="training", seed=1337,
        image_size=image_size, batch_size=batch_size)
    validation_data = tf.keras.preprocessing.image_dataset_from_directory(
        PET_IMAGES_DIR,
        validation_split=0.2, subset="validation", seed=1337,
        image_size=image_size, batch_size=batch_size)

    return train_data, validation_data


def visualize_data(dataset):
    plt.figure(figsize=(10, 10))
    for images, labels in dataset.take(1):
        for i in range(9):
            ax = plt.subplot(3, 3, i + 1)
            plt.imshow(images[i].numpy().astype("uint8"))
            plt.title(int(labels[i]))
            plt.axis("off")
            plt.show()


if __name__ == '__main__':
    # get_data()

    image_size = (180, 180)
    batch_size = 32

    train_ds, val_ds = get_dataset(image_size, batch_size)

    # visualize_data(train_data)

    # When you don't have a large image dataset, it's a good practice to artificially introduce
    # sample diversity by applying random yet realistic transformations to the training images,
    # such as random horizontal flipping or small random rotations. This helps expose the model
    # to different aspects of the training data while slowing down overfitting.

    data_augmentation = keras.Sequential([
        layers.RandomFlip("horizontal"),
        layers.RandomRotation(0.1),
    ])

    # Our image are already in a standard size (180x180), as they are being yielded as contiguous float32 batches by
    # our dataset. However, their RGB channel values are in the [0, 255] range. This is not ideal for a neural
    # network; in general you should seek to make your input values small. Here, we will standardize values to be in
    # the [0, 1] by using a Rescaling layer at the start of our model.
    ''' Example:
        inputs = keras.Input(shape=input_shape)
        x = data_augmentation(inputs)
        x = layers.Rescaling(1./255)(x)
    '''

    augmented_train_ds = train_ds.map(lambda x, y: (data_augmentation(x, training=True), y))

    # Let's make sure to use buffered prefetching so we can yield data from disk without having I/O becoming blocking:
    train_ds_buf = train_ds.prefetch(buffer_size=32)
    train_ds_buf = val_ds.prefetch(buffer_size=32)

    input_shape = image_size + (3,)
    num_classes = 2

    inputs = keras.Input(shape=input_shape)
    # Image augmentation block
    x = data_augmentation(inputs)

    # Entry block
    x = layers.Rescaling(1.0 / 255)(x)
    x = layers.Conv2D(32, 3, strides=2, padding="same")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation("relu")(x)

    x = layers.Conv2D(64, 3, padding="same")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation("relu")(x)

    previous_block_activation = x  # Set aside residual

    for size in [128, 256, 512, 728]:
        x = layers.Activation("relu")(x)
        x = layers.SeparableConv2D(size, 3, padding="same")(x)
        x = layers.BatchNormalization()(x)

        x = layers.Activation("relu")(x)
        x = layers.SeparableConv2D(size, 3, padding="same")(x)
        x = layers.BatchNormalization()(x)

        x = layers.MaxPooling2D(3, strides=2, padding="same")(x)

        # Project residual
        residual = layers.Conv2D(size, 1, strides=2, padding="same")(
            previous_block_activation
        )
        x = layers.add([x, residual])  # Add back residual
        previous_block_activation = x  # Set aside next residual

    x = layers.SeparableConv2D(1024, 3, padding="same")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation("relu")(x)

    x = layers.GlobalAveragePooling2D()(x)
    if num_classes == 2:
        activation = "sigmoid"
        units = 1
    else:
        activation = "softmax"
        units = num_classes

    x = layers.Dropout(0.5)(x)
    outputs = layers.Dense(units, activation=activation)(x)

    model = keras.Model(inputs, outputs)

    # keras.utils.plot_model(model, show_shapes=True)

    epochs = 1

    callbacks = [
        keras.callbacks.ModelCheckpoint("save_at_{epoch}.h5"),
    ]
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss="binary_crossentropy",
                  metrics=["accuracy"], )
    model.fit(train_ds_buf, epochs=epochs, callbacks=callbacks, validation_data=train_ds_buf)



    img = keras.preprocessing.image.load_img(f"{PET_IMAGES_DIR}/Cat/6779.jpg", target_size=image_size)
    img_array = keras.preprocessing.image.img_to_array(img)
    img_array = tf.expand_dims(img_array, 0)  # Create batch axis

    predictions = model.predict(img_array)
    score = predictions[0]
    print("This image is %.2f percent cat and %.2f percent dog."
        % (100 * (1 - score), 100 * score))