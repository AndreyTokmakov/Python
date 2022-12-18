import pandas as pd

DATA_FILE = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\StudentsPerformance.csv"


def MathScore_GroupedBy_Gender():
    data = pd.read_csv(DATA_FILE)

    mean = data.groupby(['gender'])['math score'].mean()
    print(mean)


# Top5 мужчин и женщин сортированных по 'math score'
def Test():
    data = pd.read_csv(DATA_FILE)

    # Внутри конкретного пола выборка отсортирована по 'math score'
    sorted = data.sort_values(['gender', 'math score'], ascending=False)
    # sorted = data.sort_values(['gender', 'math score'])

    result = sorted.groupby(['gender']).head()
    print(result)


if __name__ == '__main__':
    MathScore_GroupedBy_Gender()
    # Test()

