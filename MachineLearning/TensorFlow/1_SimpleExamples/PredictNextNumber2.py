
import tensorflow as tf
import numpy as np
from typing import List
from tensorflow import keras


def Finabochi(N) -> List:
    a = 0;
    b = 1;

    list = [a, b]
    for i in range(N):
        c = a + b;
        a = b
        b = c
        list.append(c)

    return list


if __name__ == '__main__':
    numbers = Finabochi(35)
    inputs = np.array(numbers, dtype=int)

    model = tf.keras.Sequential([
        keras.layers.Dense(units=1, input_shape=[1])
    ])

    model.compile(optimizer='sgd', loss='mean_squared_error')
    model.fit(inputs, epochs=500)

    # Make predictions:
    # for val in [4.1, 5, 10]:
    #     print(f"For number {val} ==> {model.predict([val])}")
