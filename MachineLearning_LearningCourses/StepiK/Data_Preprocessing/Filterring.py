import pandas as pd
import numpy as np

DATA_FILE = "/home/andtokm/DiskS/Projects/Python_IDEA/MachineLearning_LearningCourses/StepiK/data/StudentsPerformance.csv"
students_data = pd.read_csv(DATA_FILE)


def Get_Column_ByName():
    # Get head part
    part = students_data.head()

    print(part.gender)
    print('----------------------- or --------------------------')
    print(part['gender'])
    print('----------------------- print if gender == male --------------------------')
    print(part.gender == 'male')


def Get_Records_Filtered_By_Field():
    # Get head part (for more readable print output)
    part = students_data.head()

    result = part.loc[part.gender == 'female']
    print(result)


def Filter_AND_Condition():
    filtered = students_data[(students_data['writing score'] > 10) & (students_data.gender == 'female')]
    print(filtered)

    # OR

    filtered1 = students_data[students_data['writing score'] > 10]
    filtered2 = filtered1[filtered1.gender == 'female']

    print(filtered2)


def GetColumns_With_Prefix():
    score_columns = [i for i in list(students_data) if 'score' in i]
    print(students_data[score_columns].head())


def GetColumns_With_Prefix2():
    score_columns = students_data.filter(like='score')
    print(score_columns)


if __name__ == '__main__':
    # Get_Column_ByName()
    # Get_Records_Filtered_By_Field()
    # Filter_AND_Condition()

    # GetColumns_With_Prefix()
    GetColumns_With_Prefix2()


    '''
    # print(students_data.head())

    print('----------------------- [3 rows x 8 columns] --------------------------')
    print(students_data.iloc[0:3])

    print('----------------------- [3 rows x 5 columns]--------------------------')
    print(students_data.iloc[0:3, 0:5])

    print('----------------------- named_data --------------------------')
    named_data = students_data.iloc[[0, 3, 4, 7, 8]]
    named_data.index = ["Cersei", "Tywin", "Gregor", "Joffrey", "Ilyn Payne"]
    print(named_data)

    print('----------------------- named_data 2 --------------------------')
    print(named_data.loc[["Cersei", "Joffrey"], ['gender', 'writing score']])
    '''
