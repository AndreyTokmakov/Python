from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List


class IPerson(ABC):

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_gender(self) -> str:
        pass

    @abstractmethod
    def get_marital_status(self) -> str:
        pass


class Criteria(ABC):

    @abstractmethod
    def meet_criteria(self, persons: List[Person]) -> List[Person]:
        pass


class Person(IPerson):

    def __init__(self, name: str, gender: str, status: str):
        self.name: str = name
        self.gender: str = gender
        self.marital_status: str = status

    def get_name(self) -> str:
        return self.name

    def get_gender(self) -> str:
        return self.gender

    def get_marital_status(self) -> str:
        return self.marital_status

    def __str__(self) -> str:
        return f'Person(Name: {self.name}, Gender: {self.gender}, Status: {self.marital_status})'

    def __repr__(self) -> str:
        return str(self)


class CriteriaMale(Criteria):

    def meet_criteria(self, persons: List[Person]) -> List[Person]:
        return [p for p in persons if p.get_gender().upper() == "MALE"]


class CriteriaFemale(Criteria):

    def meet_criteria(self, persons: List[Person]) -> List[Person]:
        return [p for p in persons if p.get_gender().upper() == "FEMALE"]


class CriteriaSingle(Criteria):

    def meet_criteria(self, persons: List[Person]) -> List[Person]:
        return [p for p in persons if p.get_marital_status().upper() == "SINGLE"]


class AndCriteria(Criteria):

    def __init__(self, first_criteria: Criteria, second_criteria: Criteria):
        self.first_criteria = first_criteria
        self.second_criteria = second_criteria

    def meet_criteria(self, persons: List[Person]) -> List[Person]:
        filtered: List[Person] = self.first_criteria.meet_criteria(persons)
        return self.second_criteria.meet_criteria(filtered)


class OrCriteria(Criteria):

    def __init__(self, first_criteria: Criteria, second_criteria: Criteria):
        self.first_criteria = first_criteria
        self.second_criteria = second_criteria

    def meet_criteria(self, persons: List[Person]) -> List[Person]:
        filtered: List[Person] = self.first_criteria.meet_criteria(persons)
        filtered.extend(self.second_criteria.meet_criteria(persons))
        return filtered


if __name__ == "__main__":
    persons_list: List[Person] = [
        Person("Robert", "Male", "Single"), Person("John", "Male", "Married"),
        Person("Laura", "Female", "Married"), Person("Diana", "Female", "Single"),
        Person("Mike", "Male", "Single"), Person("Bobby", "Male", "Single")
    ]

    males: Criteria = CriteriaMale()
    females: Criteria = CriteriaFemale()
    single: Criteria = CriteriaSingle()
    single_males: Criteria = AndCriteria(males, single)
    single_or_females: Criteria = OrCriteria(females, single)

    print(f'Males  : {males.meet_criteria(persons_list)}')
    print(f'Females: {females.meet_criteria(persons_list)}')
    print(f'Single : {single.meet_criteria(persons_list)}')
    print(f'\nSingle Males   : {single_males.meet_criteria(persons_list)}')
    print(f'Single Females : {single_or_females.meet_criteria(persons_list)}')

