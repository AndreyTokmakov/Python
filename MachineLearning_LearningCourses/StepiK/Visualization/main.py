from collections import defaultdict

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import seaborn as sns

DATA_FILE = "S:\\Projects\\Python_IDEA\\MachineLearning_LearningCourses\\StepiK\\data\\dataset_209770_6.txt"
GENOME_DATA = "S:\\Projects\\Python_IDEA\\MachineLearning_LearningCourses\\StepiK\\data\\genome_matrix.csv"
DOTA_DATASET = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\dota_hero_stats.csv"
IRIS = "S:\Projects\Python_IDEA\MachineLearning_LearningCourses\StepiK\data\\iris.csv"

if __name__ == '__main__':
    # data = pd.read_csv(DATA_FILE, sep=' ')
    iris_data = pd.read_csv(IRIS)

    print(iris_data)



    # plt.show()
