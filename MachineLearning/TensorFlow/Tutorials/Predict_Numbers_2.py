
import numpy as np
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense

if __name__ == '__main__':
    level1 = Dense(units=1, input_shape=[1])
    model = Sequential([level1])
    model.compile(optimizer='sgd', loss='mean_squared_error')

    xs = np.array([-1.0, 0.0, 1.0, 2.0, 3.0, 4.0], dtype=float)
    ys = np.array([-3.0, -1.0, 1.0, 3.0, 5.0, 7.0], dtype=float)

    model.fit(xs, ys, epochs=500)

    value = 10;
    print(f"Prediction for value {value} is {model.predict([value])}")
    print(f"Here is what I learned: {level1.get_weights()}")