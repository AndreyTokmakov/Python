from pathlib import Path
import pandas as pd
import numpy as np


data_folder: Path = Path("/home/andtokm/DiskS/Temp/PANDAS_DATA")

submissions_data: Path = data_folder.joinpath("submissions_data_train.csv")
event_data: Path = data_folder.joinpath("event_data_train.csv")


if __name__ == "__main__":
    data = pd.read_csv(submissions_data)

    print(data)
