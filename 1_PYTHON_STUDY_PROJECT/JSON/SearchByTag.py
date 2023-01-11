import json

json_file = "S:\\Temp\\JSON\\Test.json"


class SearchByTag:
    # Item parameter text value:
    ITEMS_PARAMETER = "items"

    # Tags parameter text value:
    TAGS_PARAMETER = "tags"

    def __init__(self, data_file, query_tag):
        try:
            with open(data_file) as data_file:
                self._data = json.load(data_file)
        except:
            self._data = None

        self.__query = query_tag

    def search(self):
        if None == self._data:
            raise StopIteration()

        items = self._data.get(self.ITEMS_PARAMETER, None)
        # Check for items existence:
        if None == items:
            return None

        yield [it for it in items if self.__query in it.get(self.TAGS_PARAMETER, {})]

    def first(self):
        if None == self._data:
            return []

        items = self._data.get(self.ITEMS_PARAMETER, None)
        # Check for items existence:
        if None == items:
            return None

        for item in items:
            tags = item.get(self.TAGS_PARAMETER, None)
            if None != tags and self.__query in tags:
                return item

        # Return None if we failed to find anything:
        return None

    # Returns hiden query value:
    @property
    def query(self):
        return self.__query


if __name__ == '__main__':
    search = SearchByTag(json_file, "crime")

    results = search.search()
    print(next(results))

    # first = search.first()
    # print(first);
