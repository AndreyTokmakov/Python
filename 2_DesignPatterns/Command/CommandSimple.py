import abc


class IReceiver(object):

    @abc.abstractmethod
    def action(self):
        raise Exception("Not implemented")


class ICommand(metaclass=abc.ABCMeta):

    def __init__(self, receiver: IReceiver):
        self._receiver = receiver

    @abc.abstractmethod
    def execute(self):
        raise Exception("Not implemented")


class Executor(object):

    def __init__(self):
        self._commands = []

    def store_command(self, command: ICommand):
        self._commands.append(command)

    def execute_commands(self):
        for command in self._commands:
            command.execute()


class ConcreteCommand(ICommand):

    def execute(self):
        self._receiver.action()


class SomeReceiver(IReceiver):

    def action(self):
        print(f'{self.__class__.__name__}::action() called')


if __name__ == "__main__":
    recv: IReceiver = SomeReceiver()
    concrete_command: ICommand = ConcreteCommand(recv)

    worker = Executor()
    worker.store_command(concrete_command)
    worker.execute_commands()
