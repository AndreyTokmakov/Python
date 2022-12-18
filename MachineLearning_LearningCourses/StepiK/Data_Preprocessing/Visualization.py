import pandas as pd

DATA_FILE = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\StudentsPerformance.csv"

if __name__ == '__main__':
    student_performance = pd.read_csv(DATA_FILE)

    # print(student_performance)

    # print(student_performance.head(5))

    # print(student_performance.tail(5))

    # print(student_performance.describe())

    print('\n----------------- Types of data in file ------------------------')
    print(student_performance.dtypes)

    print('\n----------------- Data shape and size ------------------------')
    print(student_performance.shape)
    print(student_performance.size)

    print('\n----------------- aggregated data by gender ------------------------')
    print(student_performance.groupby('gender').aggregate({'writing score': 'mean'}))
