
import numpy
# import tensorflow as tf
from typing import List

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

    a = numpy.array(numbers[:-1])  # all except the last one
    b = numpy.array(numbers[-1:])  # only the last one

    print(a)
    print(b)

    '''
    # Build the model --> Set up the layers
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(units = 1, input_shape = [1])
    ])
    '''

