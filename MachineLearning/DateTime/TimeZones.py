import pandas as pd
from pandas._libs.tslibs.timestamps import Timestamp

if __name__ == '__main__':
    # Создать метку datetime
    pd.Timestamp('2017-05-01 06:00:00', tz='Europe/London')
    Timestamp('2017-05-01 06:00:00+0100', tz='Europe/London')

    # Создать метку datetime
    date = pd.Timestamp('2017-05-01 06:00:00')

    # Задать часовой пояс
    date_in_london = date.tz_localize('Europe/London')

    # Показать метку datetime
    print(date_in_london)

    # Мы также можем выполнить преобразование в другой часовой пояс:
    # Изменить часовой пояс
    date_in_africa = date_in_london.tz_convert('Africa/Abidjan')

    print(date_in_africa)
