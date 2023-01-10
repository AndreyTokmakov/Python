
import abc


class IStrategy(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def execute(self, a: int, b: int) -> int:
        pass


class AddStrategy(IStrategy):

    def execute(self, a: int, b: int) -> int:
        return a + b


class SubtractStrategy(IStrategy):

    def execute(self, a: int, b: int) -> int:
        return a - b


class MultiplyStrategy(IStrategy):

    def execute(self, a: int, b: int) -> int:
        return a * b


class Context(object):

    def __init__(self, strategy: IStrategy = None):
        self.strategy: IStrategy = strategy

    def set_strategy(self, strategy: IStrategy):
        self.strategy: IStrategy = strategy

    def apply_strategy(self, a: int, b: int) -> int:
        return self.strategy.execute(a, b)


if __name__ == '__main__':
    ctx: Context = Context()
    for strategy in [AddStrategy(), SubtractStrategy(), MultiplyStrategy()]:
        ctx.set_strategy(strategy)
        result: int = ctx.apply_strategy(5, 3)
        print(result)


