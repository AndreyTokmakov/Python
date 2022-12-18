import pandas as pd

if __name__ == '__main__':
    columns = ['type', 'value', 'roman_value']
    data = [
        ['One', 1, 'I'],
        ['Two', 2, 'II'],
        ['Three', 3, 'III'],
        ['Four', 4, 'IIII'],
        ['Five', 5, 'V'],
    ]
    my_data = pd.DataFrame(data=data, columns=columns)

    # x = my_data['type', 'roman_value']

    # print(x.iloc[0:2])
    # print(my_data[["type", "value"]].iloc[0:2])
    data = my_data[["type", "value"]]

    data = data.drop(data.index[[1]])

    print(data)
