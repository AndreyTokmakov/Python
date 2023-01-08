from __future__ import annotations
from abc import ABC, abstractmethod, ABCMeta, abstractproperty


class IState(metaclass=ABCMeta):

    # @abstractmethod
    # @property
    @abstractproperty
    def name(self) -> str:
        pass

    @abstractmethod
    def freeze(self, context: IStateContext) -> None:
        pass

    @abstractmethod
    def heat(self, context: IStateContext) -> None:
        pass


class IStateContext(metaclass=ABCMeta):

    @abstractmethod
    def set_state(self, state: IState) -> None:
        pass


class State(IState, metaclass=ABCMeta):

    def __init__(self, state_name: str) -> None:
        self.__name = state_name

    @property
    def name(self) -> str:
        return self.__name


class StateContext(IStateContext):

    def __init__(self, state: IState) -> None:
        self.__state = state

    def Freeze(self) -> None:
        print(f'Freezing {self.__state.name}')
        self.__state.freeze(self)

    def Heat(self) -> None:
        print(f'Heating {self.__state.name}')
        self.__state.heat(self)

    def set_state(self, state: IState) -> None:
        self.__state = state


class SolidState(State):

    def __init__(self) -> None:
        super().__init__(self.__class__.__name__)

    def freeze(self, context: IStateContext) -> None:
        print("Nothing happens")

    def heat(self, context: IStateContext) -> None:
        context.set_state(LiquidState())


class LiquidState(State):

    def __init__(self) -> None:
        super().__init__(self.__class__.__name__)

    def freeze(self, context: IStateContext) -> None:
        context.set_state(SolidState())

    def heat(self, context: IStateContext) -> None:
        context.set_state(GasState())


class GasState(State):

    def __init__(self) -> None:
        super().__init__(self.__class__.__name__)

    def freeze(self, context: IStateContext) -> None:
        context.set_state(LiquidState())

    def heat(self, context: IStateContext) -> None:
        print("Nothing happens")


if __name__ == "__main__":
    ctx: StateContext = StateContext(SolidState())

    ctx.Heat()
    ctx.Heat()
    ctx.Heat()

    ctx.Freeze()
    ctx.Freeze()
    ctx.Freeze()
