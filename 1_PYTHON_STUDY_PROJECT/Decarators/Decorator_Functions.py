import functools
import time


def retry(func):
    def _wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except:
            time.sleep(1)
            # Try once more
            try:
                func(*args, **kwargs)
            except:
                pass

    return _wrapper


def Retry():
    @retry
    def might_fail():
        print("might_fail")
        raise Exception

    might_fail()


# -------------------------------------------------------------------------------------

def retry_max(max_retries):
    def retry_decorator(func):
        def _wrapper(*args, **kwargs):
            for _ in range(max_retries):
                try:
                    func(*args, **kwargs)
                except Exception as exc:
                    time.sleep(1)

        return _wrapper

    return retry_decorator


def RetryMax():
    @retry_max(2)
    def might_fail():
        print("might_fail")
        raise Exception

    might_fail()


# -----------------------------------------------------------------------------------------

def timer(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        runtime = time.perf_counter() - start
        print(f"{func.__name__} took {runtime:.4f} secs")
        return result

    return _wrapper


def EstimateTime():

    @timer
    def complex_calculation():
        """Some complex calculation."""
        time.sleep(0.5)
        return 42

    res = complex_calculation()
    print(f'result: {res}')


if __name__ == '__main__':
    # Retry()
    # RetryMax()
    EstimateTime()
