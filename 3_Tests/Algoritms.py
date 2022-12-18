import math


def boat_speed():
    speed = 20.0  # still watter speed
    dist: int = 40
    time: float = 5.5  # Hours to goes downstream and comes back

    x = abs((2 * dist * speed - time * speed * speed) / time)
    print(math.sqrt(x))


if __name__ == '__main__':

    boat_speed()
