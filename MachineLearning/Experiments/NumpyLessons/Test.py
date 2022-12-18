import sys
import numpy as np
import math

# TODO: https://sohabr.net/habr/post/323720/
if __name__ == '__main__':
    # Let's create a training sample:
    data_inputs = np.array([[3, 5], [5, 1], [10, 2]])
    data_outputs = np.array([[75, 82, 93]]).T

    # Let's create a training sample and normalize the input and output data.
    # We normalize the input data in this way: we take each value and divide by the maximum of all values.
    # The output varies from 0 to 100. Divide each number by 100.
    data_inputs = data_inputs / np.amax(data_inputs, axis=0)
    data_outputs = data_outputs / 100

    # Let there be three neurons in the hidden layer, which have two synapses each.
    # Number of synapses = number of inputs. And there will be one output neuron in the output layer,
    # which has three synapses, since the signal is transmitted by three hidden neurons.
    syn0 = 2 * np.random.random((2, 3)) - 1
    syn1 = 2 * np.random.random((3, 1)) - 1

    epochs = 10_000;

    # We will submit the data again and again 10,000 times.
    # 1. supply input signals to the input layer.
    # 2. From the input layer, we transfer synapses to the hidden layer,
    # 3. summarize
    # 4. run through the activation function in each neuron.
    # 5. send it to the output layer, process it and get a response.
    for j in range(epochs):
        X = data_inputs
        Y = data_outputs
        hidden = 1 / (1 + np.exp(-(np.dot(X, syn0))))
        output = 1 / (1 + np.exp(-(np.dot(hidden, syn1))))

        # We calculate the local error, send it by synapses, correct it by the delta rule.
        output_delta = (Y - output) * (output * (1 - output))
        hidden_delta = output_delta.dot(syn1.T) * (hidden * (1 - hidden))
        syn1 += hidden.T.dot(output_delta)
        syn0 += X.T.dot(hidden_delta)



    print(syn0)
    print(syn1)
    print('Done')