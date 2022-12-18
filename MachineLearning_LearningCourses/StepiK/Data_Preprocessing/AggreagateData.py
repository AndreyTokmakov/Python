import pandas as pd

DATA_FILE = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\StudentsPerformance.csv"

if __name__ == '__main__':
    data = pd.read_csv(DATA_FILE)

    # Как различается среднее и дисперсия оценок по предметам у групп
    # студентов со стандартным или урезанным ланчем
    print(data.groupby('lunch').aggregate({
        'math score': ['count', 'mean', 'var'],
        'reading score': ['count', 'mean', 'var'],
        'writing score': ['count', 'mean', 'var']
    }))
