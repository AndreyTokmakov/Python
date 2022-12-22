import time
import datetime


def IntTime():
    now = datetime.datetime.now()
    timeInt = int(time.mktime(now.timetuple()))
    print(timeInt);


def TimeStr():
    a = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(a)


def isLeapYear():
    import calendar

    for year in range(1900, 1920):
        print(f'is {year} Leap yeap: {calendar.isleap(year)}')


def Range_BetweenDates():
    start = datetime.datetime.strptime("2019-02-01", "%Y-%m-%d")
    end = datetime.datetime.strptime("2019-02-28", "%Y-%m-%d")
    date_generated = [start + datetime.timedelta(days=x) for x in range(0, (end-start).days)]

    for date in date_generated:
        print(date.strftime("%d-%m-%Y"))


def Range_BetweenDates_2():
    start = datetime.datetime.strptime("2019-02-01", "%Y-%m-%d")
    end = datetime.datetime.strptime("2019-02-28", "%Y-%m-%d")

    for ordinal in range(start.toordinal(), end.toordinal() + 1):
        print(datetime.date.fromordinal(ordinal))


def create_manually():
    d = datetime.datetime(year=2020, month=1, day=31, hour=13, minute=14, second=31)
    print(d)


if __name__ == '__main__':
    # IntTime();
    # TimeStr();
    # isLeapYear()

    # Range_BetweenDates()
    # Range_BetweenDates_2()
    create_manually()

