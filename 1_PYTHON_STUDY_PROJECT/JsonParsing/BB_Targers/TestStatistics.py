
import json;

class TestStatistics(object):
    
    def __init__(self, *args, **kwargs):
        object.__init__(self, *args, **kwargs);


if __name__ == '__main__':
    jsonData = dict(module = "Updater tests", test = "3434");
    
    stats = dict(passed = 18, failed = 2);
    
    jsonData["run stats"] = stats;
    
    jsonObj = json.dumps(jsonData);
    print(jsonObj);