from operator import attrgetter


class User:
    def __init__(self, user_id):
        self.user_id = user_id

    def __repr__(self):
        return 'User({})'.format(self.user_id)


def sort_test1():
    users = [User(23), User(3), User(99)]
    print(users)

    users = sorted(users, key=lambda u: u.user_id)
    print(users)


def sort_test2():
    users = [User(23), User(3), User(99)]
    print(users)

    users = sorted(users, key=attrgetter('user_id'))
    print(users)


if __name__ == '__main__':
    sort_test1()
    sort_test2()
