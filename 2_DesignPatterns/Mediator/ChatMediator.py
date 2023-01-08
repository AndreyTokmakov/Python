from __future__ import annotations

import abc
from typing import Dict


class IChatRoom(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def send_message(self, msg: str, use_id: str) -> None:
        pass

    @abc.abstractmethod
    def add_user(self, user: User) -> None:
        pass


class User(metaclass=abc.ABCMeta):

    def __init__(self,
                 mediator: IChatRoom,
                 user_id: str,
                 name: str):
        self.mediator: IChatRoom = mediator
        self.id: str = user_id
        self.name: str = name

    @abc.abstractmethod
    def send(self, msg: str, user_id: str) -> None:
        pass

    @abc.abstractmethod
    def receive(self, msg: str) -> None:
        pass


class ChatRoom(IChatRoom):

    def __init__(self):
        super(ChatRoom, self).__init__()
        self.users_map: Dict[str, User] = {}

    def add_user(self, user: User) -> None:
        self.users_map[user.id] = user

    def send_message(self, msg: str, user_id: str) -> None:
        self.users_map[user_id].receive(msg)


class ChatUser(User):

    def __init__(self, room: IChatRoom, user_id: str, name: str):
        super().__init__(room, user_id, name)

    def send(self, msg: str, user_id: str) -> None:
        print(f'{self.name} ==> Sending Message : {msg}')
        self.mediator.send_message(msg, user_id)

    def receive(self, msg: str) -> None:
        print(f'{self.name} <== Received Message : {msg}')


if __name__ == "__main__":
    chatroom = ChatRoom()

    user1 = ChatUser(chatroom, "1", "Alex")
    user2 = ChatUser(chatroom, "2", "Brian")
    user3 = ChatUser(chatroom, "3", "Charles")
    user4 = ChatUser(chatroom, "4", "David")

    chatroom.add_user(user1)
    chatroom.add_user(user2)
    chatroom.add_user(user3)
    chatroom.add_user(user4)

    user1.send("Hello brian", "2")
    user2.send("Hey buddy", "1")
