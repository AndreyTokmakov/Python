'''
Created on Nov 26, 2020
@author: AndTokm
'''

from functools import reduce


class MAP():

    @staticmethod
    def Test1():
        old_list = ['1', '2', '3', '4', '5', '6', '7']
        new_list = list(map(int, old_list))
        print(new_list)  # -> [1, 2, 3, 4, 5, 6, 7]

    @staticmethod
    def Test2():
        # list of Strings to ints:
        def miles_to_kilometers(num_miles):
            """ Converts miles to the kilometers """
            return num_miles * 1.6

        mile_distances = [1.0, 6.5, 17.4, 2.4, 9]
        kilometer_distances = list(map(miles_to_kilometers, mile_distances))
        print(kilometer_distances)

    @staticmethod
    def Test2_Lambda():
        mile_distances = [1.0, 6.5, 17.4, 2.4, 9]
        kilometer_distances = list(map(lambda x: x * 1.6, mile_distances))
        print(kilometer_distances)  # --> [1.6, 10.4, 27.84, 3.84, 14.4]

    @staticmethod
    def Test_TwoLists():
        l1 = [1, 2, 3]
        l2 = [4, 5, 6]

        new_list = list(map(lambda x, y: x + y, l1, l2))
        print(new_list)

    @staticmethod
    def Test_TwoLists_Lambda():
        l1 = [1, 2, 3]
        l2 = [4, 5, 6]

        new_list = list(map(lambda x, y: + y, l1, l2))
        print(new_list)


''' Filter function test class: '''


class FILTER():

    @staticmethod
    def Test1():
        mixed = ['11', '2211', '2233', '331133', '225566']
        results = list(filter(lambda x: x == '11', mixed))
        print(results)


''' reduce function test class: '''


class REDUCE():

    @staticmethod
    def Sum_List():
        items = [1, 2, 3, 4, 5]
        sum_all = reduce(lambda x, y: x + y, items)
        print(sum_all)

    @staticmethod
    def Find_Max():
        items = [1, 24, 17, 14, 9, 32, 2]
        all_max = reduce(lambda a, b: a if (a > b) else b, items)
        print(all_max)


''' zip function test class: '''


class ZIP():

    @staticmethod
    def Test1():
        a = [1, 2, 3]
        b = "xyz"
        c = (None, True)

        res = list(zip(a, b, c))
        print(res)


if __name__ == '__main__':
    # MAP.Test1(); # list of Strings to ints:
    # MAP.Test2()    # Converts miles to the kilometers
    # MAP.Test2_Lambda()    # Converts miles to the kilometers
    # MAP.Test_TwoLists()
    # MAP.Test_TwoLists_Lambda()

    # FILTER.Test1()

    # REDUCE.Sum_List()
    # REDUCE.Find_Max()

    ZIP.Test1()
