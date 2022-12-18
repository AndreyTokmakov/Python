
raw_str = 'This\nstring has\tsome whitespaces\r\n'

char_map = {
    ord('\n'): ' ',
    ord('\t'): ' ',
    ord('\r'): None
}

if __name__ == '__main__':
    print(raw_str)

    text = raw_str.translate(char_map)

    print(text)