import datetime
import json


class Data(object):

    def __init__(self):
        self.value: int = 0
        self.name: str = "Some_Name1"
        self.timestamp: datetime.datetime = datetime.datetime.utcnow()

    def toJson(self) -> str:
        return json.dumps(self, default=lambda o: o.__dict__)

    def toJson2(self) -> str:
        return json.dumps({'timestamp': str(self.timestamp), })


def data_2_json__Internal_DICT():
    data = Data()
    str = json.dumps(data.__dict__)
    print(str)


def data_2_json_method():
    data = Data()
    print(data.toJson())


def data_2_json_method_manually():
    d = Data()
    print(d.toJson2())


if __name__ == '__main__':
    # data_2_json__Internal_DICT()
    # data_2_json_method()
    data_2_json_method_manually()

