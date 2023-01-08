
def run_once():
    print("run_once() entered")
    if getattr(run_once, 'has_run', False):
        return

    run_once.has_run = True
    print("run_once() called")


if __name__ == '__main__':
    run_once()
    run_once()
    run_once()