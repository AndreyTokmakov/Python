import pandas as pd

DATA_FILE1 = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\titanic.csv"
DATA_FILE = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\StudentsPerformance.csv"
DATA_FILE2 = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\column_hell.csv"
DOTA_DATASET = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\dota_hero_stats.csv"
ACCOUNTS_DATASET = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\accountancy.csv"
ALGAE_DATASET = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\algae.csv"


if __name__ == '__main__':
    # data = pd.read_csv(DOTA_DATASET)


    '''print(data.groupby('lunch').aggregate({
        'math score': ['count', 'mean', 'var'],
        'reading score': ['count', 'mean', 'var'],
        'writing score': ['count', 'mean', 'var']
    }))
    '''


    '''
    score_colums  = [i for i in list(data) if 'score' in i]
    print(data[score_colums].head())
    '''

    '''
    selected_columns = data.filter(like='-')
    print(selected_columns.columns)
    '''

    '''
    dota_data = pd.read_csv(DOTA_DATASET)
    result = dota_data.groupby(['attack_type', 'primary_attr']).count()
    print(result)
    '''

    '''
    data = pd.read_csv(ACCOUNTS_DATASET)
    sorted = data.sort_values(['Type', 'Salary'], ascending=False)
    result = sorted.groupby(['Type']).head()
    print(result)
    '''

    data = pd.read_csv(ALGAE_DATASET)
    sorted = data.sort_values(['group', 'sucrose'], ascending=False)
    result = sorted.groupby(['group']).max()
    print(result)