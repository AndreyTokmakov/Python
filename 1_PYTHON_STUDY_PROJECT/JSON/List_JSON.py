import json


def List_to_JSON_1():
    l = [41, 58, 63]
    jsonStr = json.dumps(l)
    print(jsonStr)


if __name__ == '__main__':
    List_to_JSON_1()
