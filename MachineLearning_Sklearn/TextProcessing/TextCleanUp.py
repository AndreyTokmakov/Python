

def PreprocessText():
    text_data = [" Interrobang. By Aishwarya Henriette ",
                 "Parking And Going. By Karl Gautier",
                 " Today Is The night. By Jarek Prakash "]

    strip_whitespace = [string.strip() for string in text_data]

    # TODO: Remove dots
    remove_dots = [string.replace(".", "") for string in strip_whitespace]

    print(remove_dots)


if __name__ == '__main__':
    PreprocessText()
