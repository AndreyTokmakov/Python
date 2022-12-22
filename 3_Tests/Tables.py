from prettytable import PrettyTable

if __name__ == "__main__":
    table = PrettyTable()
    table.field_names = ['Names', 'Age', 'City']

    table.add_row(['Name5', 25, 'City5'])
    table.add_row(['Name4', 24, 'City4'])
    table.add_row(['Name3', 23, 'City3'])
    table.add_row(['Name2', 22, 'City2'])
    table.add_row(['Name1', 21, 'City1'])

    table.align = 'r'
    table.sortby = 'Age'

    print(table)
