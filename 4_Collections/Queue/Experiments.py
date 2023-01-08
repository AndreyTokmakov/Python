

class Book:
    def __init__(self, title, due_date):
        self.title = title
        self.due_date = due_date

    def __repr__(self):
        return f'Boot({self.title}, {self.due_date})'


def add_book(queue, book):
    queue.append(book)
    queue.sort(key=lambda x: x.due_date, reverse=True)


def Book_Test():
    queue = []

    add_book(queue, Book('Don Quixote', '2019-06-07'))
    add_book(queue, Book('Frankenstein', '2019-06-05'))
    add_book(queue, Book('Les Misérables', '2019-06-08'))
    add_book(queue, Book('War and Peace', '2019-06-03'))

    print(queue)


if __name__ == '__main__':
    pass
