from abc import ABC, abstractmethod


class Subject(ABC):

    @abstractmethod
    def request(self) -> None:
        pass


class RealSubject(Subject):

    def request(self) -> None:
        print(f"{self.__class__.__name__}: Handling request.")


class Proxy(Subject):

    def __init__(self, real_subject: Subject) -> None:
        self._real_subject = real_subject

    def request(self) -> None:
        if self.check_access():
            self._real_subject.request()
            self.log_access()

    def check_access(self) -> bool:
        print(f"{self.__class__.__name__}: Checking access prior to firing a real request.")
        return True

    def log_access(self) -> None:
        print(f"{self.__class__.__name__}: Logging the time of request.", end="")


def client_code(subject: Subject) -> None:
    # ...
    subject.request()
    # ...


if __name__ == "__main__":
    obj: Subject = RealSubject()
    client_code(obj)

    print("")

    proxy = Proxy(obj)
    client_code(proxy)
